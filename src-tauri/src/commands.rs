//! Tauri 命令：文件解析 / 详情 / 统计 / 实时捕获。

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use pcap::{Capture, Device};
use serde::Serialize;
use tauri::ipc::Channel;
use tauri::State;

use crate::model::{DetailData, InterfaceInfo, PacketRow, ParseResult, Stats};
use crate::pipeline::{device_from_tree, parse_file, Analyzer, Entry};
use crate::protobuf::ProtoEngine;
use crate::reassembly::FlowKey;
use crate::zenoh;

#[derive(Default)]
pub struct AppState {
    analyzer: Arc<Mutex<Option<Analyzer>>>,
    live: Mutex<Option<LiveHandle>>,
}

struct LiveHandle {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

// ---------- 文件模式 ----------

#[tauri::command]
pub fn parse_pcap(
    state: State<'_, AppState>,
    pcap_path: String,
    proto_dir: Option<String>,
) -> Result<ParseResult, String> {
    let analyzer = parse_file(&pcap_path, proto_dir.as_deref())?;
    let result = ParseResult {
        rows: analyzer.entries.iter().map(|e| e.row.clone()).collect(),
        warnings: analyzer.warnings.clone(),
    };
    *state.analyzer.lock().unwrap() = Some(analyzer);
    Ok(result)
}

#[tauri::command]
pub fn get_detail(state: State<'_, AppState>, index: usize) -> Result<DetailData, String> {
    let guard = state.analyzer.lock().unwrap();
    let analyzer = guard.as_ref().ok_or("尚未解析任何数据")?;
    analyzer.detail(index).ok_or_else(|| format!("行 {index} 不存在"))
}

#[tauri::command]
pub fn get_stats(state: State<'_, AppState>) -> Result<Stats, String> {
    let guard = state.analyzer.lock().unwrap();
    let analyzer = guard.as_ref().ok_or("尚未解析任何数据")?;
    Ok(analyzer.stats.clone())
}

// ---------- 实时模式 ----------

#[tauri::command]
pub fn count_proto_files(dir: String) -> Result<usize, String> {
    fn walk(d: &std::path::Path, out: &mut usize) -> std::io::Result<()> {
        for e in std::fs::read_dir(d)? {
            let p = e?.path();
            if p.is_dir() {
                walk(&p, out)?;
            } else if p.extension().and_then(|x| x.to_str()) == Some("proto") {
                *out += 1;
            }
        }
        Ok(())
    }
    let mut n = 0;
    walk(std::path::Path::new(&dir), &mut n).map_err(|e| e.to_string())?;
    Ok(n)
}

#[tauri::command]
pub fn list_interfaces() -> Result<Vec<InterfaceInfo>, String> {
    let mut out = Vec::new();
    for dev in Device::list().map_err(|e| e.to_string())? {
        let addresses = dev
            .addresses
            .iter()
            .filter_map(|a| a.addr.to_string().parse::<std::net::IpAddr>().ok())
            .filter(|ip| ip.is_ipv4())
            .map(|ip| ip.to_string())
            .collect();
        let alias = adapter_alias(&dev.name).unwrap_or_default();
        out.push(InterfaceInfo {
            name: dev.name.clone(),
            desc: dev.desc.unwrap_or_default(),
            alias,
            addresses,
        });
    }
    Ok(out)
}

/// 从注册表查网卡连接别名（如 "以太网"、"WLAN"）。
/// device name 形如 \Device\NPF_{GUID}，别名在
/// HKLM\SYSTEM\...\Network\{class}\{GUID}\Connection\Name
#[cfg(windows)]
fn adapter_alias(device_name: &str) -> Option<String> {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;

    let guid = device_name
        .split('{')
        .nth(1)?
        .trim_end_matches('}')
        .trim_end_matches(')');
    let key_path = format!(
        r"SYSTEM\CurrentControlSet\Control\Network\{{4D36E972-E325-11CE-BFC1-08002BE10318}}\{{{guid}}}\Connection"
    );
    let hk = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(key_path).ok()?;
    hk.get_value::<String, _>("Name").ok()
}

#[cfg(not(windows))]
fn adapter_alias(_device_name: &str) -> Option<String> {
    None
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum LiveEvent {
    /// rows: 新增行；updates: 被更新配对信息的已有行（按 index 覆盖）
    Rows { rows: Vec<PacketRow>, updates: Vec<PacketRow>, total: usize },
    Error { message: String },
}

#[tauri::command]
pub fn start_capture(
    state: State<'_, AppState>,
    interface: String,
    bpf: String,
    proto_dir: Option<String>,
    on_rows: Channel<LiveEvent>,
) -> Result<(), String> {
    let engine = match &proto_dir {
        Some(dir) => Some(ProtoEngine::load(dir).map_err(|e| format!("加载 proto 失败: {e}"))?),
        None => None,
    };

    let mut cap = Capture::from_device(interface.as_str())
        .map_err(|e| format!("打开网卡失败: {e}"))?
        .promisc(true)
        .timeout(500) // 毫秒；让 stop 能及时生效
        .open()
        .map_err(|e| format!("启动捕获失败(需要管理员权限?): {e}"))?;
    if !bpf.is_empty() {
        cap.filter(&bpf, true)
            .map_err(|e| format!("BPF 过滤器错误: {e}"))?;
    }

    // 新的 analyzer（实时数据 append 进去，get_detail/get_stats 通用）
    {
        let mut g = state.analyzer.lock().unwrap();
        *g = Some(Analyzer::empty(engine));
    }
    let shared = state.analyzer.clone();

    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let shared2 = shared.clone();

    let handle = std::thread::spawn(move || {
        let mut live = LiveParser::new();
        loop {
            if stop2.load(Ordering::Relaxed) {
                break;
            }
            match cap.next_packet() {
                Ok(pkt) => {
                    let ts_us = (pkt.header.ts.tv_sec as i64) * 1_000_000
                        + (pkt.header.ts.tv_usec as i64);
                    let msgs = live.feed(pkt.data, ts_us);
                    if msgs.is_empty() {
                        continue;
                    }
                    // append 进共享 analyzer
                    let mut rows = Vec::new();
                    let mut updates = Vec::new();
                    let mut guard = shared2.lock().unwrap();
                    if let Some(an) = guard.as_mut() {
                        for m in msgs {
                            let out = an.append_live(m);
                            rows.push(out[0].clone());
                            if out.len() > 1 {
                                updates.push(out[1].clone());
                            }
                        }
                        let total = an.entries.len();
                        drop(guard);
                        let _ = on_rows.send(LiveEvent::Rows { rows, updates, total });
                    }
                }
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(e) => {
                    let _ = on_rows.send(LiveEvent::Error { message: format!("捕获错误: {e}") });
                    break;
                }
            }
        }
        let _ = on_rows.send(LiveEvent::Rows { rows: Vec::new(), updates: Vec::new(), total: 0 });
    });

    *state.live.lock().unwrap() = Some(LiveHandle {
        stop,
        handle: Some(handle),
    });
    Ok(())
}

#[tauri::command]
pub fn stop_capture(state: State<'_, AppState>) -> Result<(), String> {
    let mut guard = state.live.lock().unwrap();
    if let Some(mut session) = guard.take() {
        session.stop.store(true, Ordering::Relaxed);
        if let Some(h) = session.handle.take() {
            let _ = h.join();
        }
    }
    Ok(())
}

/// 实时解析器：增量 TCP 重组 + Zenoh batch 切分
pub(crate) struct LiveParser {
    sessions: zenoh::Sessions,
    pub(crate) flows: HashMap<FlowKey, LiveFlow>,
    base_ts: Option<i64>,
    pending: Vec<zenoh::ParsedMessage>,
}

#[derive(Clone)]
pub(crate) struct LiveFlow {
    base_seq: Option<u32>,
    next_rel: u64,
    pending: BTreeMap<u64, (Vec<u8>, i64)>,
    stream: Vec<u8>,
    /// (字节偏移, 时间戳)
    stream_marks: Vec<(usize, i64)>,
}

impl LiveParser {
    pub(crate) fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            flows: HashMap::new(),
            base_ts: None,
            pending: Vec::new(),
        }
    }

    /// 返回本次新解析出的消息
    pub(crate) fn feed(&mut self, frame: &[u8], ts_us: i64) -> Vec<zenoh::ParsedMessage> {
        let Some(seg) = crate::pipeline::parse_tcp_frame(frame) else {
            return Vec::new();
        };
        if seg.payload.is_empty() {
            return Vec::new();
        }
        let key = FlowKey {
            src: format!("{}:{}", seg.src_ip, seg.src_port),
            dst: format!("{}:{}", seg.dst_ip, seg.dst_port),
        };
        let flow = self.flows.entry(key.clone()).or_insert_with(|| LiveFlow {
            base_seq: None,
            next_rel: 0,
            pending: BTreeMap::new(),
            stream: Vec::new(),
            stream_marks: Vec::new(),
        });
        let base = *flow.base_seq.get_or_insert(seg.seq);
        let rel = seg.seq.wrapping_sub(base) as u64;
        // 同 seq 冲突保留更长的段（过滤 keepalive 探测）
        match flow.pending.get(&rel) {
            Some((old, _)) if old.len() >= seg.payload.len() => {}
            _ => {
                flow.pending.insert(rel, (seg.payload, ts_us));
            }
        }

        // 按序取出（有缺口则等待）。
        // 至少缓存 2 段才提交最前段：Windows keepalive 探测与真数据段同 seq，
        // 探测包（零字节垃圾）常先到达，延迟一段给"更长段替换"留出机会，
        // 否则流开头被污染后 batch 切分永久卡死。
        while flow.pending.len() >= 2 {
            let Some(&first) = flow.pending.keys().next() else {
                break;
            };
            if first > flow.next_rel {
                break;
            }
            let (mut data, ts) = flow.pending.remove(&first).unwrap();
            if first + data.len() as u64 <= flow.next_rel {
                continue; // 重传
            }
            let skip = (flow.next_rel - first) as usize;
            if skip > 0 {
                data.drain(..skip);
            }
            flow.stream_marks.push((flow.stream.len(), ts));
            flow.stream.extend_from_slice(&data);
            flow.next_rel = first + (skip + data.len()) as u64;
        }

        // 从 stream 前部按 batch 边界切分解析
        let (a, b) = normalize(&key.src, &key.dst);
        let is_a = key.src == a;
        let mut consumed = 0usize;
        while consumed + 2 <= flow.stream.len() {
            let len =
                u16::from_le_bytes([flow.stream[consumed], flow.stream[consumed + 1]]) as usize;
            if len == 0 || consumed + 2 + len > flow.stream.len() {
                break;
            }
            let batch = flow.stream[consumed + 2..consumed + 2 + len].to_vec();
            let batch_ts = flow
                .stream_marks
                .iter()
                .rev()
                .find(|(off, _)| *off <= consumed)
                .map(|(_, t)| *t)
                .unwrap_or(ts_us);
            if self.base_ts.is_none() {
                self.base_ts = Some(batch_ts);
            }
            zenoh::parse_batch(
                &batch,
                0,
                batch_ts,
                (a.clone(), b.clone()),
                is_a,
                &mut self.sessions,
                &mut self.pending,
            );
            consumed += 2 + len;
        }
        flow.stream.drain(..consumed);
        for (off, _) in flow.stream_marks.iter_mut() {
            *off = off.saturating_sub(consumed);
        }
        flow.stream_marks.retain(|(off, _)| *off < flow.stream.len() + 1);

        // topic 延迟解析：mapping 表已在本流 declare 时更新，统一 resolve
        let mut msgs = std::mem::take(&mut self.pending);
        zenoh::resolve_all(&mut msgs, &(a.clone(), b.clone()), is_a, &self.sessions);
        msgs
    }
}

fn normalize(src: &str, dst: &str) -> (String, String) {
    let a = src.split(':').next().unwrap_or(src);
    let b = dst.split(':').next().unwrap_or(dst);
    if a <= b {
        (src.to_string(), dst.to_string())
    } else {
        (dst.to_string(), src.to_string())
    }
}

impl Analyzer {
    pub fn empty(engine: Option<ProtoEngine>) -> Self {
        Self {
            entries: Vec::new(),
            warnings: Vec::new(),
            stats: Default::default(),
            engine,
            rid_map: HashMap::new(),
            pair: HashMap::new(),
        }
    }

    /// 实时模式追加一条消息，返回行数据
    /// 实时模式追加一条消息。返回需通知前端的行：[新增行, (可选)被更新配对的 Request 行]
    pub fn append_live(&mut self, m: zenoh::ParsedMessage) -> Vec<PacketRow> {
        let msg_class = m.msg_type.split('(').next().unwrap_or("").to_string();
        let base = m.ts_us; // 实时模式相对基准=各自首包（由前端以第一行为准）
        let (outer_type, any_type, summary, device_id) = match &self.engine {
            Some(eng) if !m.payload.is_empty() => {
                let r = eng.decode_wrapper(&msg_class, &m.payload);
                let device = device_from_tree(&r.tree);
                (
                    r.outer_type.clone(),
                    r.any_type.clone(),
                    r.summary.clone(),
                    device,
                )
            }
            _ => (String::new(), String::new(), String::new(), String::new()),
        };
        let direction = if m.msg_type.starts_with("Push") {
            "→服务器"
        } else {
            "→设备"
        };
        let index = self.entries.len();
        let row = PacketRow {
            index,
            frame_number: m.frame_number,
            ts_us: m.ts_us,
            rel_us: m.ts_us - base,
            src: String::new(),
            dst: String::new(),
            direction: direction.to_string(),
            msg_type: m.msg_type.clone(),
            topic: m.topic.clone(),
            topic_complete: m.topic_complete,
            outer_type,
            any_type,
            device_id,
            summary,
            rid: m.rid,
            pair_index: None,
            rtt_ms: None,
            payload_len: m.payload.len(),
            warnings: if m.topic_complete {
                Vec::new()
            } else {
                vec!["topic mapping 缺失".into()]
            },
        };
        let entry = Entry {
            row,
            payload: m.payload,
            msg_class: msg_class.clone(),
            flow_src: String::new(),
            flow_dst: String::new(),
            session_id: String::new(),
        };
        self.entries.push(entry);
        let index = self.entries.len() - 1;

        // 请求响应配对（增量）：每个 Response 都回指 Request 并计算 RTT；
        // Request 指向最新 Response（该行需推送给前端更新）
        let mut updated_req: Option<PacketRow> = None;
        if let Some(rid) = m.rid {
            match msg_class.as_str() {
                "Request" => {
                    self.rid_map.insert((String::new(), rid), index);
                }
                "Response" | "ResponseFinal" => {
                    if let Some(req_i) = self.rid_map.get(&(String::new(), rid)).copied() {
                        self.pair.insert(index, req_i);
                        self.pair.insert(req_i, index);
                        let rtt = {
                            let req = &self.entries[req_i].row;
                            if req.msg_type.starts_with("Request") {
                                Some((m.ts_us - req.ts_us) as f64 / 1000.0)
                            } else {
                                None
                            }
                        };
                        self.entries[index].row.pair_index = Some(req_i);
                        self.entries[index].row.rtt_ms = rtt;
                        let req_row = &mut self.entries[req_i].row;
                        if req_row.msg_type.starts_with("Request") {
                            req_row.pair_index = Some(index);
                            req_row.rtt_ms = rtt;
                            updated_req = Some(req_row.clone());
                        }
                    }
                }
                _ => {}
            }
        }

        let new_row = self.entries[index].row.clone();
        match updated_req {
            Some(req_row) => vec![new_row, req_row],
            None => vec![new_row],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 实时模式配对验证：pcap 帧序模拟 LiveParser + append_live
    #[test]
    fn live_pairing_works() {
        let frames = crate::source::read_file("../../测试用例/33333.pcapng").unwrap();
        let mut live = LiveParser::new();
        let mut an = Analyzer::empty(None);
        for f in &frames {
            for m in live.feed(&f.data, f.ts_us) {
                an.append_live(m);
            }
        }
        let pairs = an.pair.len() / 2;
        let with_rtt = an.entries.iter().filter(|e| e.row.rtt_ms.is_some()).count();
        println!("实时配对数: {pairs}, 带 RTT: {with_rtt}");

        assert!(pairs > 20, "实时配对过少: {pairs}");
    }
}
