//! Zenoh 1.x (Zenoh080) 线协议解析器（TCP unicast 子集）。
//! 参考实现：eclipse-zenoh/zenoh zenoh-codec crate。
//!
//! 线格式要点：
//! - TCP 流 = 若干 batch：2 字节 LE 长度 + payload
//! - batch payload = 若干 TransportMessage：header(flags高3位|mid低5位) + body
//! - Frame(0x05): sn(varint) + [exts] + NetworkMessage*
//! - varint = LEB128；string/bytes = varint len + bytes
//! - ext header = Z(0x80)|ENC(0x60)|M(0x10)|ID(0x0f)；ENC: 0=Unit 1=Z64(varint) 2=ZBuf(len+bytes)

use std::collections::HashMap;

#[allow(clippy::doc_markdown)]
pub mod mid {
    // transport
    pub const T_OAM: u8 = 0x00;
    pub const INIT: u8 = 0x01;
    pub const OPEN: u8 = 0x02;
    pub const CLOSE: u8 = 0x03;
    pub const KEEP_ALIVE: u8 = 0x04;
    pub const FRAME: u8 = 0x05;
    pub const FRAGMENT: u8 = 0x06;
    pub const JOIN: u8 = 0x07;
    // network
    pub const N_OAM: u8 = 0x1f;
    pub const DECLARE: u8 = 0x1e;
    pub const PUSH: u8 = 0x1d;
    pub const REQUEST: u8 = 0x1c;
    pub const RESPONSE: u8 = 0x1b;
    pub const RESPONSE_FINAL: u8 = 0x1a;
    pub const INTEREST: u8 = 0x19;
    // data body
    pub const PUT: u8 = 0x01;
    pub const DEL: u8 = 0x02;
    pub const QUERY: u8 = 0x03;
    pub const REPLY: u8 = 0x04;
    pub const ERR: u8 = 0x05;
    // declare body
    pub const D_KEYEXPR: u8 = 0x00;
    pub const U_KEYEXPR: u8 = 0x01;
    pub const D_SUBSCRIBER: u8 = 0x02;
    pub const U_SUBSCRIBER: u8 = 0x03;
    pub const D_QUERYABLE: u8 = 0x04;
    pub const U_QUERYABLE: u8 = 0x05;
    pub const D_TOKEN: u8 = 0x06;
    pub const U_TOKEN: u8 = 0x07;
    pub const D_FINAL: u8 = 0x1a;
    // ext id
    pub const EXT_QOS: u8 = 0x01;
    pub const EXT_NODE_ID: u8 = 0x02;
    pub const EXT_BODY: u8 = 0x05;
}

const FLAG_Z: u8 = 0x80;
const FLAG_N: u8 = 0x20;
const FLAG_M_MAPPING: u8 = 0x40;
const ENC_UNIT: u8 = 0x00;
const ENC_Z64: u8 = 0x20;
const ENC_ZBUF: u8 = 0x40;

#[derive(Debug, Clone)]
pub struct ParsedMessage {
    /// "Push(Put)" / "Request(Query)" / "Response(Reply)" / "Response(Err)" /
    /// "ResponseFinal" / "Declare(KeyExpr)" / "Declare(Subscriber)" / "Interest" / …
    pub msg_type: String,
    pub topic: String,
    pub topic_complete: bool,
    /// 待解析的 key 引用（scope != 0 时需要等全部 declare 解析完再统一 resolve）
    pub key_ref: Option<KeyRef>,
    pub rid: Option<u32>,
    pub sn: Option<u32>,
    pub payload: Vec<u8>,
    /// 主帧号（UI 显示）
    pub frame_number: u32,
    /// 消息关联的全部帧（TCP 分段时一个 batch 跨多帧）
    pub frame_numbers: Vec<u32>,
    pub ts_us: i64,
}

/// 消息对 mapping 的引用
#[derive(Debug, Clone)]
pub struct KeyRef {
    pub scope: u16,
    pub suffix: String,
    /// true = M flag 置位（用发送方声明表）
    pub mapping_sender: bool,
}

/// 一个 TCP 会话（双向）的 mapping 表
#[derive(Default)]
pub struct Session {
    /// A 端（地址序小）声明的 mapping
    pub map_a: HashMap<u16, String>,
    /// B 端声明的 mapping
    pub map_b: HashMap<u16, String>,
}

/// 全部会话状态
pub type Sessions = HashMap<(String, String), Session>;

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
    fn u8(&mut self) -> Option<u8> {
        let b = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }
    fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.remaining() < n {
            return None;
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Some(s)
    }
    fn u16le(&mut self) -> Option<u16> {
        let b = self.bytes(2)?;
        Some(u16::from_le_bytes([b[0], b[1]]))
    }
    /// LEB128 varint
    fn varint(&mut self) -> Option<u64> {
        let mut v: u64 = 0;
        let mut i = 0;
        loop {
            let b = self.u8()?;
            v |= ((b & 0x7f) as u64) << i;
            if b & 0x80 == 0 {
                return Some(v);
            }
            i += 7;
            if i > 63 {
                return None;
            }
        }
    }
    fn zstr(&mut self) -> Option<String> {
        let len = self.varint()? as usize;
        let b = self.bytes(len)?;
        Some(String::from_utf8_lossy(b).into_owned())
    }
    fn zbuf(&mut self) -> Option<Vec<u8>> {
        let len = self.varint()? as usize;
        Some(self.bytes(len)?.to_vec())
    }
    /// uhlc Timestamp: time varint + id_size varint + id
    fn hlc_timestamp(&mut self) -> Option<()> {
        let _time = self.varint()?;
        let sz = self.varint()? as usize;
        self.bytes(sz)?;
        Some(())
    }
    /// Encoding: varint id(低位=S) + [len + schema]
    fn encoding(&mut self) -> Option<()> {
        let id = self.varint()?;
        if id & 1 != 0 {
            let sz = self.varint()? as usize;
            self.bytes(sz)?;
        }
        Some(())
    }
    /// 读一个 ext（header 已读），返回 (ext_id, has_more)
    fn ext(&mut self, header: u8) -> Option<(u8, bool)> {
        match header & 0x60 {
            ENC_UNIT => {}
            ENC_Z64 => {
                self.varint()?;
            }
            ENC_ZBUF => {
                self.zbuf()?;
            }
            _ => return None,
        }
        Some((header & 0x0f, header & FLAG_Z != 0))
    }
    /// 跳过扩展链
    fn skip_exts(&mut self, mut has: bool) -> Option<()> {
        while has {
            let h = self.u8()?;
            let (_, more) = self.ext(h)?;
            has = more;
        }
        Some(())
    }
}

/// 从 TCP 字节流解析全部 Zenoh 消息
pub fn parse_stream(
    data: &[u8],
    frame_at: impl Fn(usize) -> u32,
    ts_at: impl Fn(u32) -> i64,
    session_key: (String, String),
    is_a: bool,
    sessions: &mut Sessions,
) -> Vec<ParsedMessage> {
    let mut out = Vec::new();
    let mut r = Reader::new(data);
    while r.remaining() >= 2 {
        let batch_len = r.u16le().unwrap_or(0) as usize;
        if batch_len == 0 || r.remaining() < batch_len {
            break;
        }
        let batch_start = r.pos;
        let frame = frame_at(batch_start);
        let ts = ts_at(frame);
        let batch = &data[batch_start..batch_start + batch_len];
        parse_batch(batch, frame, ts, session_key.clone(), is_a, sessions, &mut out);
        r.pos = batch_start + batch_len;
    }
    out
}

/// 解析单个 batch（供文件与实时管线共用）
pub fn parse_batch(
    batch: &[u8],
    frame: u32,
    ts: i64,
    session_key: (String, String),
    is_a: bool,
    sessions: &mut Sessions,
    out: &mut Vec<ParsedMessage>,
) {
    let mut r = Reader::new(batch);
    while r.remaining() >= 1 {
        let pos = r.pos;
        let header = match r.u8() {
            Some(h) => h,
            None => break,
        };
        match header & 0x1f {
            mid::FRAME => {
                parse_frame(&mut r, header, frame, ts, session_key.clone(), is_a, sessions, out)
            }
            _ => {
                // init/open/keepalive/close/join/oam/fragment：尽力跳过（失败则放弃本 batch）
                if skip_transport(&mut r, header & 0x1f, header).is_none() {
                    break;
                }
            }
        }
        if r.pos <= pos {
            break;
        }
    }
}

fn skip_transport(r: &mut Reader, mid: u8, header: u8) -> Option<()> {
    match mid {
        mid::CLOSE => {
            let _reason = r.u8()?;
            r.skip_exts(true)
        }
        mid::KEEP_ALIVE => r.skip_exts(true),
        mid::T_OAM => {
            // |Z|ENC|OAM| + id varint + [len+bytes if ENC!=Unit] + [exts]
            let _id = r.varint()?;
            match (header >> 5) & 0b11 {
                0b01 => {
                    r.varint()?; // u64
                }
                0b10 => {
                    r.zbuf()?; // ZBuf
                }
                _ => {}
            }
            r.skip_exts(header & FLAG_Z != 0)
        }
        // INIT/OPEN/JOIN/FRAGMENT 的字段宽度依赖协商结果，无法可靠跳过，放弃该 batch
        _ => None,
    }
}

fn parse_frame(
    r: &mut Reader,
    header: u8,
    frame: u32,
    ts: i64,
    session_key: (String, String),
    is_a: bool,
    sessions: &mut Sessions,
    out: &mut Vec<ParsedMessage>,
) {
    let _reliable = header & 0x20 != 0;
    let sn = match r.varint() {
        Some(v) => v as u32,
        None => return,
    };
    if r.skip_exts(header & FLAG_Z != 0).is_none() {
        return;
    }

    while r.remaining() >= 1 {
        let pos = r.pos;
        let h = match r.u8() {
            Some(h) => h,
            None => break,
        };
        let mut msg = match h & 0x1f {
            mid::PUSH => parse_push(r, h, frame, ts, session_key.clone(), is_a, sessions),
            mid::REQUEST => parse_request(r, h, frame, ts, session_key.clone(), is_a, sessions),
            mid::RESPONSE => parse_response(r, h, frame, ts, session_key.clone(), is_a, sessions),
            mid::RESPONSE_FINAL => parse_response_final(r, h, frame, ts),
            mid::DECLARE => parse_declare(r, h, frame, ts, session_key.clone(), is_a, sessions),
            mid::INTEREST => parse_interest(r, h, frame, ts),
            mid::N_OAM => parse_network_oam(r, h, frame, ts),
            _ => None,
        };
        if let Some(m) = msg.as_mut() {
            m.sn = Some(sn);
        }
        match msg {
            Some(m) => out.push(m),
            None => break,
        }
        if r.pos <= pos {
            break;
        }
    }
}

/// wire_expr：scope varint + [suffix]。scope=0 直接用 suffix；否则延迟 resolve。
/// mapping_sender=true 表示 M flag 置位（用发送方声明表）
fn read_key_ref(r: &mut Reader, has_suffix: bool, mapping_sender: bool) -> (String, bool, Option<KeyRef>) {
    let scope = r.varint().unwrap_or(0) as u16;
    let suffix = if has_suffix {
        r.zstr().unwrap_or_default()
    } else {
        String::new()
    };
    if scope == 0 {
        (suffix, true, None)
    } else {
        (String::new(), false, Some(KeyRef { scope, suffix, mapping_sender }))
    }
}

/// 全部流解析完成后统一 resolve topic（此时 mapping 表已完整）
pub fn resolve_all(msgs: &mut [ParsedMessage], session_key: &(String, String), is_a: bool, sessions: &Sessions) {
    for m in msgs.iter_mut() {
        let Some(kr) = m.key_ref.take() else {
            continue;
        };
        let sess = sessions.get(session_key);
        let table = match (kr.mapping_sender, is_a) {
            (true, true) | (false, false) => sess.map(|s| &s.map_a),
            (true, false) | (false, true) => sess.map(|s| &s.map_b),
        };
        match table.and_then(|t| t.get(&kr.scope)) {
            Some(base) => {
                m.topic = format!("{base}{}", kr.suffix);
                m.topic_complete = true;
            }
            None => {
                m.topic = format!("~{}/{}", kr.scope, kr.suffix);
                m.topic_complete = false;
            }
        }
    }
}

fn parse_push(
    r: &mut Reader,
    header: u8,
    frame: u32,
    ts: i64,
    _session_key: (String, String),
    _is_a: bool,
    _sessions: &mut Sessions,
) -> Option<ParsedMessage> {
    let (topic, complete, key_ref) = read_key_ref(r, header & FLAG_N != 0, header & FLAG_M_MAPPING != 0);
    r.skip_exts(header & FLAG_Z != 0)?;
    // PushBody: PUT(0x01) | DEL(0x02)
    let bh = r.u8()?;
    let (kind, payload) = match bh & 0x1f {
        mid::PUT => {
            if bh & 0x20 != 0 {
                r.hlc_timestamp()?; // T flag
            }
            if bh & 0x40 != 0 {
                r.encoding()?; // E flag
            }
            r.skip_exts(bh & FLAG_Z != 0)?;
            ("Push(Put)", r.zbuf()?)
        }
        mid::DEL => {
            if bh & 0x20 != 0 {
                r.hlc_timestamp()?;
            }
            r.skip_exts(bh & FLAG_Z != 0)?;
            ("Push(Del)", Vec::new())
        }
        _ => return None,
    };
    Some(ParsedMessage {
        msg_type: kind.into(),
        topic,
        topic_complete: complete,
        key_ref,
        rid: None,
        sn: None,
        payload,
        frame_number: frame,
        frame_numbers: vec![frame],
        ts_us: ts,
    })
}

fn parse_request(
    r: &mut Reader,
    header: u8,
    frame: u32,
    ts: i64,
    _session_key: (String, String),
    _is_a: bool,
    _sessions: &mut Sessions,
) -> Option<ParsedMessage> {
    let rid = r.varint()? as u32;
    let (topic, complete, key_ref) =
        read_key_ref(r, header & FLAG_N != 0, header & FLAG_M_MAPPING != 0);
    r.skip_exts(header & FLAG_Z != 0)?;

    // RequestBody：QUERY(0x03) 或 PUT(0x01)
    let bh = r.u8()?;
    let (kind, payload) = match bh & 0x1f {
        mid::QUERY => {
            // |Z|P|C| QUERY | + consolidation(if C) + parameters(if P) + exts
            if bh & 0x20 != 0 {
                r.u8()?; // consolidation
            }
            if bh & 0x40 != 0 {
                r.zstr()?; // parameters
            }
            // Query exts：ID=3 (ZBuf: encoding字节+payload) / ID=4 (ZBuf: payload)
            let mut payload = Vec::new();
            let mut has = bh & FLAG_Z != 0;
            while has {
                let eh = r.u8()?;
                match eh & 0x0f {
                    0x03 => {
                        payload = strip_encoding_byte(r.zbuf()?);
                        has = eh & FLAG_Z != 0;
                    }
                    0x04 => {
                        payload = r.zbuf()?;
                        has = eh & FLAG_Z != 0;
                    }
                    _ => {
                        let (_, more) = r.ext(eh)?;
                        has = more;
                    }
                }
            }
            ("Request(Query)", payload)
        }
        mid::PUT => ("Request(Put)", extract_put_payload(r, bh)),
        _ => return None,
    };
    Some(ParsedMessage {
        msg_type: kind.into(),
        topic,
        topic_complete: complete,
        key_ref,
        rid: Some(rid),
        sn: None,
        payload,
        frame_number: frame,
        frame_numbers: vec![frame],
        ts_us: ts,
    })
}

/// ExtBody ZBuf 内容 = [encoding_id:u8] + payload → 剥掉 encoding 字节
fn strip_encoding_byte(data: Vec<u8>) -> Vec<u8> {
    data.into_iter().skip(1).collect()
}

/// 内嵌 Put/Del 编码 → 提取 Put payload
fn extract_put_payload(r: &mut Reader, h: u8) -> Vec<u8> {
    let res = (|| -> Option<()> {
        if h & 0x20 != 0 {
            r.hlc_timestamp()?;
        }
        if h & 0x40 != 0 {
            r.encoding()?;
        }
        r.skip_exts(h & FLAG_Z != 0)?;
        Some(())
    })();
    if res.is_none() {
        return Vec::new();
    }
    r.zbuf().unwrap_or_default()
}

fn parse_response(
    r: &mut Reader,
    header: u8,
    frame: u32,
    ts: i64,
    _session_key: (String, String),
    _is_a: bool,
    _sessions: &mut Sessions,
) -> Option<ParsedMessage> {
    let rid = r.varint()? as u32;
    let (topic, complete, key_ref) =
        read_key_ref(r, header & FLAG_N != 0, header & FLAG_M_MAPPING != 0);
    r.skip_exts(header & FLAG_Z != 0)?;
    // ResponseBody: REPLY(0x04) | ERR(0x05)
    let bh = r.u8()?;
    let (kind, payload) = match bh & 0x1f {
        mid::REPLY => {
            if bh & 0x20 != 0 {
                r.u8()?; // consolidation
            }
            r.skip_exts(bh & FLAG_Z != 0)?;
            // ReplyBody = Put/Del 消息（header 直接在流上，不经过中间 ZBuf）
            let ih = r.u8()?;
            let payload = match ih & 0x1f {
                mid::PUT => extract_put_payload(r, ih),
                _ => Vec::new(),
            };
            ("Response(Reply)", payload)
        }
        mid::ERR => {
            if bh & 0x40 != 0 {
                r.encoding()?;
            }
            r.skip_exts(bh & FLAG_Z != 0)?;
            ("Response(Err)", r.zbuf()?)
        }
        _ => return None,
    };
    Some(ParsedMessage {
        msg_type: kind.into(),
        topic,
        topic_complete: complete,
        key_ref,
        rid: Some(rid),
        sn: None,
        payload,
        frame_number: frame,
        frame_numbers: vec![frame],
        ts_us: ts,
    })
}

fn parse_response_final(r: &mut Reader, header: u8, frame: u32, ts: i64) -> Option<ParsedMessage> {
    let rid = r.varint()? as u32;
    r.skip_exts(header & FLAG_Z != 0)?;
    Some(ParsedMessage {
        msg_type: "ResponseFinal".into(),
        key_ref: None,
        topic: String::new(),
        topic_complete: true,
        rid: Some(rid),
        sn: None,
        payload: Vec::new(),
        frame_number: frame,
        frame_numbers: vec![frame],
        ts_us: ts,
    })
}

fn parse_declare(
    r: &mut Reader,
    header: u8,
    frame: u32,
    ts: i64,
    session_key: (String, String),
    is_a: bool,
    sessions: &mut Sessions,
) -> Option<ParsedMessage> {
    if header & FLAG_N != 0 {
        let _interest = r.varint()?; // interest_id（I flag 复用 bit5）
    }
    r.skip_exts(header & FLAG_Z != 0)?;
    let bh = r.u8()?;
    let msg_type;
    let mut topic = String::new();
    // 所有 declare body 的 N/M flag 都在 body header 字节（bh），格式统一：
    // id varint + scope varint + suffix(if N)
    let decl_n = bh & FLAG_N != 0;
    match bh & 0x1f {
        mid::D_KEYEXPR => {
            msg_type = "Declare(KeyExpr)".into();
            let id = r.varint()? as u16;
            let scope = r.varint()? as u16;
            let suffix = if decl_n {
                r.zstr().unwrap_or_default()
            } else {
                String::new()
            };
            let full = if scope == 0 {
                suffix
            } else {
                let sess = sessions.entry(session_key.clone()).or_default();
                let table = if is_a { &sess.map_a } else { &sess.map_b };
                table.get(&scope).cloned().unwrap_or_default() + &suffix
            };
            let sess = sessions.entry(session_key).or_default();
            if is_a {
                sess.map_a.insert(id, full.clone());
            } else {
                sess.map_b.insert(id, full.clone());
            }
            topic = full;
        }
        mid::U_KEYEXPR => {
            msg_type = "Undeclare(KeyExpr)".into();
            let _id = r.varint()?;
        }
        mid::D_SUBSCRIBER => {
            msg_type = "Declare(Subscriber)".into();
            let _id = r.varint()?;
            topic = read_we(r, decl_n);
        }
        mid::U_SUBSCRIBER => {
            msg_type = "Undeclare(Subscriber)".into();
            let _id = r.varint()?;
            let _ = r.skip_exts(true); // ext_wire_expr
        }
        mid::D_QUERYABLE => {
            msg_type = "Declare(Queryable)".into();
            let _id = r.varint()?;
            topic = read_we(r, decl_n);
            let _ = r.skip_exts(bh & FLAG_Z != 0); // ext_info 等
        }
        mid::U_QUERYABLE => {
            msg_type = "Undeclare(Queryable)".into();
            let _id = r.varint()?;
            let _ = r.skip_exts(true);
        }
        mid::D_TOKEN => {
            msg_type = "Declare(Token)".into();
            let _id = r.varint()?;
            topic = read_we(r, decl_n);
        }
        mid::U_TOKEN => {
            msg_type = "Undeclare(Token)".into();
            let _id = r.varint()?;
            let _ = r.skip_exts(true);
        }
        mid::D_FINAL => {
            msg_type = "Declare(Final)".into();
        }
        _ => return None,
    }
    Some(ParsedMessage {
        msg_type,
        topic,
        topic_complete: true,
        key_ref: None,
        rid: None,
        sn: None,
        payload: Vec::new(),
        frame_number: frame,
        frame_numbers: vec![frame],
        ts_us: ts,
    })
}

/// declare 公共的 wire_expr 编码：scope varint + suffix(if N，N 来自 body header)
fn read_we(r: &mut Reader, has_suffix: bool) -> String {
    let scope = r.varint().unwrap_or(0) as u16;
    let suffix = if has_suffix {
        r.zstr().unwrap_or_default()
    } else {
        String::new()
    };
    if scope == 0 {
        suffix
    } else {
        format!("~{scope}/{suffix}")
    }
}

fn parse_interest(r: &mut Reader, header: u8, frame: u32, ts: i64) -> Option<ParsedMessage> {
    // |Z|Mod(2)|INTEREST|  + id varint + [options byte + key] if Mod!=Final + [exts]
    let _id = r.varint()?;
    let mode = (header >> 5) & 0b11;
    if mode != 0 {
        // Final=0；其它模式有 options + key
        let options = r.u8()?;
        let restricted = options & 0x10 != 0; // R
        let named = options & 0x20 != 0; // N
        if restricted {
            let _scope = r.varint()?;
            if named {
                r.zstr()?;
            }
        }
    }
    r.skip_exts(header & FLAG_Z != 0)?;
    Some(ParsedMessage {
        msg_type: "Interest".into(),
        key_ref: None,
        topic: String::new(),
        topic_complete: true,
        rid: None,
        sn: None,
        payload: Vec::new(),
        frame_number: frame,
        frame_numbers: vec![frame],
        ts_us: ts,
    })
}

/// network 层 OAM：|Z|ENC(2)|OAM| + id varint + exts + (ENC body)
fn parse_network_oam(r: &mut Reader, header: u8, frame: u32, ts: i64) -> Option<ParsedMessage> {
    let _id = r.varint()?;
    r.skip_exts(header & FLAG_Z != 0)?;
    match (header >> 5) & 0b11 {
        0b01 => {
            r.varint()?; // u64
        }
        0b10 => {
            r.zbuf()?; // ZBuf
        }
        _ => {}
    }
    Some(ParsedMessage {
        msg_type: "OAM".into(),
        key_ref: None,
        topic: String::new(),
        topic_complete: true,
        rid: None,
        sn: None,
        payload: Vec::new(),
        frame_number: frame,
        frame_numbers: vec![frame],
        ts_us: ts,
    })
}
