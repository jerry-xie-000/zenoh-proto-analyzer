//! 解析管线：帧 → 以太网/IPv4/TCP 解析 → 流重组 → Zenoh → protobuf → 行列表 + 详情。

use std::collections::HashMap;

use crate::model::{DetailData, Kv, PacketRow, Stats};
use crate::protobuf::ProtoEngine;
use crate::reassembly::{FlowKey, StreamAssembler};
use crate::source;
use crate::zenoh::{self, Sessions};

/// 一条消息的完整解析产物（含详情所需缓存）
pub struct Entry {
    pub row: PacketRow,
    /// payload hex 行（懒生成也行，直接存）
    pub payload: Vec<u8>,
    pub msg_class: String, // Push/Request/Response/…
    pub flow_src: String,
    pub flow_dst: String,
    /// 会话级（pair 查找用）
    pub session_id: String,
}

pub struct Analyzer {
    pub entries: Vec<Entry>,
    pub warnings: Vec<String>,
    pub stats: Stats,
    pub engine: Option<ProtoEngine>,
    /// 请求配对状态（实时模式增量维护；文件模式构建时一次性回填）
    pub rid_map: HashMap<(String, u32), usize>,
    pub pair: HashMap<usize, usize>,
    /// 帧号 → (时间戳µs, 原始以太网帧)（保存 pcapng 用）
    pub frames_data: HashMap<u32, (i64, Vec<u8>)>,
}

/// 以太网/IP/TCP 解析结果
pub struct TcpSegment {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub payload: Vec<u8>,
}

pub fn parse_tcp_frame(data: &[u8]) -> Option<TcpSegment> {
    // 以太网：6+6+2；支持一层 VLAN (0x8100)
    if data.len() < 14 {
        return None;
    }
    let mut ethertype = u16::from_be_bytes([data[12], data[13]]);
    let mut off = 14;
    if ethertype == 0x8100 && data.len() >= 18 {
        ethertype = u16::from_be_bytes([data[16], data[17]]);
        off = 18;
    }
    if ethertype != 0x0800 {
        return None; // 只要 IPv4
    }
    let ip = &data[off..];
    if ip.len() < 20 {
        return None;
    }
    if ip[0] >> 4 != 4 {
        return None;
    }
    let ihl = (ip[0] & 0x0f) as usize * 4;
    if ihl < 20 || ip.len() < ihl {
        return None;
    }
    if ip[9] != 6 {
        return None; // 只要 TCP
    }
    let src_ip = format!("{}.{}.{}.{}", ip[12], ip[13], ip[14], ip[15]);
    let dst_ip = format!("{}.{}.{}.{}", ip[16], ip[17], ip[18], ip[19]);
    let tcp = &ip[ihl..];
    if tcp.len() < 20 {
        return None;
    }
    let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
    let doff = (tcp[12] >> 4) as usize * 4;
    if doff < 20 || tcp.len() < doff {
        return None;
    }
    Some(TcpSegment {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        seq,
        payload: tcp[doff..].to_vec(),
    })
}

pub fn parse_file(pcap_path: &str, proto_dir: Option<&str>) -> Result<Analyzer, String> {
    let frames = source::read_file(pcap_path).map_err(|e| e.to_string())?;

    let mut assembler = StreamAssembler::new();
    // 帧号 → ts
    let mut frame_ts: HashMap<u32, i64> = HashMap::new();
    for (i, f) in frames.iter().enumerate() {
        frame_ts.insert((i + 1) as u32, f.ts_us);
        if let Some(seg) = parse_tcp_frame(&f.data) {
            assembler.add_segment(
                FlowKey {
                    src: format!("{}:{}", seg.src_ip, seg.src_port),
                    dst: format!("{}:{}", seg.dst_ip, seg.dst_port),
                },
                seg.seq,
                &seg.payload,
                (i + 1) as u32,
            );
        }
    }

    let streams = assembler.finish();
    let mut sessions: Sessions = HashMap::new();
    let mut all: Vec<ParsedEntry> = Vec::new();

    // 第一遍：逐流解析，构建各会话 mapping 表（topic 引用延迟 resolve）
    for (key, stream) in streams {
        let (a, b) = normalize_session(&key.src, &key.dst);
        let is_a = key.src == a;
        let frame_at = |off: usize| -> u32 { stream.frame_at(off) };
        let ts_at = |f: u32| -> i64 { frame_ts.get(&f).copied().unwrap_or(0) };
        let msgs = zenoh::parse_stream(
            &stream.data,
            frame_at,
            ts_at,
            (a.clone(), b.clone()),
            is_a,
            &mut sessions,
        );
        for m in msgs {
            all.push(ParsedEntry {
                msg: m,
                src: key.src.clone(),
                dst: key.dst.clone(),
                sess_key: (a.clone(), b.clone()),
                is_a,
                session: format!("{a} ⇄ {b}"),
            });
        }
    }

    // 第二遍：mapping 表完整后统一解析 topic（按 会话+方向 分组，方向影响查表）
    {
        let mut by_session: HashMap<((String, String), bool), Vec<usize>> = HashMap::new();
        for (i, e) in all.iter().enumerate() {
            by_session
                .entry((e.sess_key.clone(), e.is_a))
                .or_default()
                .push(i);
        }
        for ((sess_key, is_a), idxs) in by_session {
            let mut slice: Vec<zenoh::ParsedMessage> =
                idxs.iter().map(|&i| all[i].msg.clone()).collect();
            zenoh::resolve_all(&mut slice, &sess_key, is_a, &sessions);
            for (&i, m) in idxs.iter().zip(slice.into_iter()) {
                all[i].msg = m;
            }
        }
    }

    // 按时间稳定排序（同时间按流内出现顺序）
    all.sort_by_key(|e| e.msg.ts_us);

    let frames_map: HashMap<u32, (i64, Vec<u8>)> = frames
        .iter()
        .enumerate()
        .map(|(i, f)| ((i + 1) as u32, (f.ts_us, f.data.clone())))
        .collect();

    let engine = match proto_dir {
        Some(dir) => match ProtoEngine::load(dir) {
            Ok(e) => Some(e),
            Err(err) => {
                return Err(format!("加载 proto 失败: {err}"));
            }
        },
        None => None,
    };

    build_analyzer(all, engine, frames_map)
}

struct ParsedEntry {
    msg: zenoh::ParsedMessage,
    src: String,
    dst: String,
    sess_key: (String, String),
    is_a: bool,
    session: String,
}

pub fn normalize_session(src: &str, dst: &str) -> (String, String) {
    let a = src.split(':').next().unwrap_or(src);
    let b = dst.split(':').next().unwrap_or(dst);
    if a <= b {
        (src.to_string(), dst.to_string())
    } else {
        (dst.to_string(), src.to_string())
    }
}

fn build_analyzer(
    all: Vec<ParsedEntry>,
    engine: Option<ProtoEngine>,
    frames_map: HashMap<u32, (i64, Vec<u8>)>,
) -> Result<Analyzer, String> {
    let mut entries = Vec::new();
    let mut warnings = Vec::new();
    let base_ts = all.first().map(|e| e.msg.ts_us).unwrap_or(0);

    // 请求响应配对：rid → Request 的 index（按会话+rid）
    let mut rid_map: HashMap<(String, u32), usize> = HashMap::new();
    let mut pair: HashMap<usize, usize> = HashMap::new(); // index → 对端 index

    let mut by_type: HashMap<String, usize> = HashMap::new();
    let mut by_topic: HashMap<String, usize> = HashMap::new();
    let mut devices: Vec<String> = Vec::new();
    let mut sessions_seen: Vec<String> = Vec::new();

    for (i, e) in all.iter().enumerate() {
        let msg = &e.msg;
        let msg_class = msg.msg_type.split('(').next().unwrap_or(&msg.msg_type).to_string();

        // protobuf 解码（外层/Any 类型 + 设备 + 摘要）
        let (outer_type, any_type, summary, device_id, payload_len) = match &engine {
            Some(eng) if msg.has_payload() => {
                let r = eng.decode_wrapper(&msg_class, &msg.payload);
                let device = device_from_tree(&r.tree);
                if !device.is_empty() && !devices.contains(&device) {
                    devices.push(device.clone());
                }
                (
                    r.outer_type.clone(),
                    r.any_type.clone(),
                    r.summary.clone(),
                    device,
                    msg.payload.len(),
                )
            }
            _ => (
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                msg.payload.len(),
            ),
        };

        let direction = if e.dst.ends_with(":7447") {
            "→设备"
        } else {
            "→服务器"
        };

        let row = PacketRow {
            index: i,
            frame_number: msg.frame_number,
            frame_numbers: msg.frame_numbers.clone(),
            ts_us: msg.ts_us,
            rel_us: msg.ts_us - base_ts,
            src: e.src.clone(),
            dst: e.dst.clone(),
            direction: direction.to_string(),
            msg_type: msg.msg_type.clone(),
            topic: msg.topic.clone(),
            topic_complete: msg.topic_complete,
            outer_type,
            any_type,
            device_id,
            summary,
            rid: msg.rid,
            pair_index: None,
            rtt_ms: None,
            payload_len,
            warnings: if msg.topic_complete {
                Vec::new()
            } else {
                vec!["topic mapping 缺失（捕获晚于会话建立）".into()]
            },
        };

        // 配对：一个 Request 可对应多个 Response（多 queryable）+ ResponseFinal，
        // 每个 Response 都回指 Request；Request 指向最新的 Response
        if let Some(rid) = msg.rid {
            match msg_class.as_str() {
                "Request" => {
                    rid_map.insert((e.session.clone(), rid), i);
                }
                "Response" | "ResponseFinal" => {
                    let key = (e.session.clone(), rid);
                    if let Some(req_i) = rid_map.get(&key).copied() {
                        pair.insert(i, req_i);
                        pair.insert(req_i, i);
                    }
                }
                _ => {}
            }
        }

        *by_type.entry(msg.msg_type.clone()).or_default() += 1;
        if !msg.topic.is_empty() {
            *by_topic.entry(topic_short(&msg.topic)).or_default() += 1;
        }
        if !sessions_seen.contains(&e.session) {
            sessions_seen.push(e.session.clone());
        }
        if !msg.topic_complete {
            warnings.push(format!(
                "#{} topic mapping 缺失: {}",
                i, msg.topic
            ));
        }

        entries.push(Entry {
            row,
            payload: msg.payload.clone(),
            msg_class,
            flow_src: e.src.clone(),
            flow_dst: e.dst.clone(),
            session_id: e.session.clone(),
        });
    }

    // 回填配对信息 + RTT（pair 含双向条目，仅 Response 侧计算 RTT）
    for (&resp_i, &req_i) in &pair {
        if !entries[resp_i].row.msg_type.starts_with("Response") {
            continue;
        }
        let rtt = {
            let req = &entries[req_i].row;
            if req.msg_type.starts_with("Request") {
                Some((entries[resp_i].row.ts_us - req.ts_us) as f64 / 1000.0)
            } else {
                None
            }
        };
        let row = &mut entries[resp_i].row;
        row.pair_index = Some(req_i);
        row.rtt_ms = rtt;
    }
    // Request 行指向最新的 Response
    for (&req_i, &resp_i) in &pair {
        if entries[req_i].row.msg_type.starts_with("Request") {
            entries[req_i].row.pair_index = Some(resp_i);
        }
    }

    let mut stats = Stats {
        total: entries.len(),
        by_type: drain_sorted(by_type),
        by_topic: drain_sorted(by_topic),
        devices,
        ts_first: entries.first().map(|e| e.row.ts_us),
        ts_last: entries.last().map(|e| e.row.ts_us),
        sessions: sessions_seen,
    };
    stats.by_type.sort_by(|a, b| b.1.cmp(&a.1));
    stats.by_topic.sort_by(|a, b| b.1.cmp(&a.1));

    Ok(Analyzer {
        entries,
        warnings,
        stats,
        engine,
        rid_map: HashMap::new(),
        pair: HashMap::new(),
        frames_data: frames_map,
    })
}

fn topic_short(t: &str) -> String {
    // 过长的 topic 截断中段
    if t.len() > 60 {
        format!("{}…{}", &t[..28], &t[t.len() - 28..])
    } else {
        t.to_string()
    }
}

fn drain_sorted(m: HashMap<String, usize>) -> Vec<(String, usize)> {
    m.into_iter().collect()
}

/// 从 wrapper 树中提取 PacketHead.device_id
pub fn device_from_tree(tree: &Option<crate::protobuf::ProtoFieldNode>) -> String {
    let Some(tree) = tree else { return String::new() };
    tree.children
        .iter()
        .find(|c| c.name == "packet_head")
        .and_then(|head| head.children.iter().find(|c| c.name == "device_id"))
        .map(|c| c.value_label.clone())
        .unwrap_or_default()
}

impl zenoh::ParsedMessage {
    fn has_payload(&self) -> bool {
        !self.payload.is_empty()
    }
}

impl Analyzer {
    pub fn detail(&self, index: usize) -> Option<DetailData> {
        let entry = self.entries.get(index)?;
        let row = &entry.row;

        let mut zenoh_fields = vec![
            Kv {
                key: "方向".into(),
                value: format!("{} → {}", row.src, row.dst),
            },
            Kv {
                key: "帧号".into(),
                value: row.frame_number.to_string(),
            },
            Kv {
                key: "消息类型".into(),
                value: row.msg_type.clone(),
            },
        ];
        if !row.topic.is_empty() {
            zenoh_fields.push(Kv {
                key: "Topic".into(),
                value: row.topic.clone(),
            });
        }
        if let Some(rid) = row.rid {
            zenoh_fields.push(Kv {
                key: "Request ID".into(),
                value: rid.to_string(),
            });
        }
        if let (Some(p), Some(rtt)) = (row.pair_index, row.rtt_ms) {
            zenoh_fields.push(Kv {
                key: "配对".into(),
                value: format!("#{} (RTT {rtt:.1} ms)", p + 1),
            });
        }
        if let Some(ts) = packet_head_ts(&self.engine, entry) {
            zenoh_fields.push(Kv {
                key: "PacketHead 时间戳".into(),
                value: ts,
            });
        }
        if let Some(dev) = row
            .summary
            .split(" · ")
            .find(|s| s.starts_with("device="))
        {
            zenoh_fields.push(Kv {
                key: "设备".into(),
                value: dev.trim_start_matches("device=").to_string(),
            });
        }

        // protobuf 树
        let proto_tree = if entry.payload.is_empty() {
            None
        } else {
            self.engine.as_ref().map(|eng| {
                eng.decode_wrapper(&entry.msg_class, &entry.payload).tree
            }).flatten()
        };

        // hex
        let hex_lines = hex_dump(&entry.payload, 256);

        Some(DetailData {
            zenoh_fields,
            proto_tree,
            hex_lines,
        })
    }
}

fn packet_head_ts(engine: &Option<ProtoEngine>, entry: &Entry) -> Option<String> {
    let eng = engine.as_ref()?;
    let r = eng.decode_wrapper(&entry.msg_class, &entry.payload);
    let tree = r.tree?;
    let head = tree.children.iter().find(|c| c.name == "packet_head")?;
    let ts = head.children.iter().find(|c| c.name == "timestamp")?;
    // 树中 Timestamp 节点的 value_label 已是本地时间字符串
    let label = ts.value_label.clone();
    if label.is_empty() {
        None
    } else {
        Some(label)
    }
}

fn hex_dump(data: &[u8], max: usize) -> Vec<String> {
    let take = data.len().min(max);
    let mut lines = Vec::new();
    for chunk in data[..take].chunks(16) {
        let mut hex_part = String::new();
        let mut ascii = String::new();
        for (i, b) in chunk.iter().enumerate() {
            hex_part.push_str(&format!("{b:02x} "));
            if i == 7 {
                hex_part.push(' ');
            }
            ascii.push(if b.is_ascii_graphic() || *b == b' ' {
                *b as char
            } else {
                '.'
            });
        }
        let pad = 50 - hex_part.len();
        lines.push(format!("{:08x}  {}{} {}", 0, hex_part, " ".repeat(pad.max(1)), ascii));
    }
    if data.len() > max {
        lines.push(format!("… 共 {} 字节", data.len()));
    }
    lines
}
