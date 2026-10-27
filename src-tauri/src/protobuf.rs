//! Protobuf 动态解码：protox 编译 .proto 目录 → prost-reflect 动态消息 → 树节点。

use std::path::Path;

use prost_reflect::{
    DescriptorPool, DynamicMessage, FieldDescriptor, Kind, MapKey, MessageDescriptor,
    ReflectMessage, Value,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtoFieldNode {
    pub name: String,
    /// message / repeated / map / scalar / enum / bytes / unknown / error
    pub kind: String,
    pub type_name: String,
    pub value_label: String,
    pub numeric: Option<f64>,
    pub hex: Option<String>,
    pub hex_total: Option<usize>,
    pub index: Option<usize>,
    pub children: Vec<ProtoFieldNode>,
}

pub struct ProtoEngine {
    pool: DescriptorPool,
}

#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    #[error("proto 编译失败: {0}")]
    Compile(String),
    #[error("描述符解析失败: {0}")]
    Decode(String),
}

impl ProtoEngine {
    /// 编译 proto 根目录下所有 .proto（含子目录，import 相对根目录）
    pub fn load(proto_dir: &str) -> Result<Self, ProtoError> {
        let files = collect_proto_files(Path::new(proto_dir))
            .map_err(|e| ProtoError::Compile(format!("扫描目录失败: {e}")))?;
        if files.is_empty() {
            return Err(ProtoError::Compile("目录下没有 .proto 文件".into()));
        }
        let set =
            protox::compile(files, [proto_dir]).map_err(|e| ProtoError::Compile(e.to_string()))?;
        let mut buf = Vec::new();
        prost_reflect::prost::Message::encode(&set, &mut buf)
            .map_err(|e| ProtoError::Decode(e.to_string()))?;
        let pool =
            DescriptorPool::decode(buf.as_slice()).map_err(|e| ProtoError::Decode(e.to_string()))?;
        Ok(Self { pool })
    }

    pub fn file_count(&self) -> usize {
        self.pool.files().count()
    }

    /// 解码外层 wrapper（PubData/Pub/ReqData/RespData/Resp）并构建树
    pub fn decode_wrapper(&self, msg_class: &str, payload: &[u8]) -> WrapperResult {
        let candidates: &[&str] = match msg_class {
            "Push" => &["pb.common.PubData", "pb.common.Pub"],
            "Request" => &["pb.common.ReqData", "pb.common.Req"],
            "Response" => &["pb.common.RespData", "pb.common.Resp"],
            _ => &[
                "pb.common.PubData",
                "pb.common.Pub",
                "pb.common.ReqData",
                "pb.common.Req",
                "pb.common.RespData",
                "pb.common.Resp",
            ],
        };
        for name in candidates {
            let Some(desc) = self.pool.get_message_by_name(name) else {
                continue;
            };
            let Ok(msg) = DynamicMessage::decode(desc.clone(), payload) else {
                continue;
            };
            if !wrapper_structure_matches(&msg, &desc) {
                continue;
            }
            return self.build_wrapper_tree(name, &msg);
        }
        WrapperResult::raw(payload)
    }

    fn build_wrapper_tree(&self, name: &str, msg: &DynamicMessage) -> WrapperResult {
        let desc = msg.descriptor();
        let short = name.rsplit('.').next().unwrap_or(name);
        let mut root = message_node(short, name, desc.full_name());
        let mut any_type = String::new();
        for (field, value) in iter_fields(msg) {
            // Any 特殊处理：解包 type_url
            if field.name() == "data" {
                if let Kind::Message(mdesc) = field.kind() {
                    if mdesc.full_name() == "google.protobuf.Any" {
                        if let Value::Message(any_msg) = &value {
                            match self.unpack_any(any_msg) {
                                Ok((ty, node)) => {
                                    any_type = ty;
                                    root.children.push(node);
                                    continue;
                                }
                                Err(reason) => {
                                    let type_url = any_msg
                                        .get_field_by_name("type_url")
                                        .map(|v| v.into_owned())
                                        .and_then(|v| match v {
                                            Value::String(s) => Some(s),
                                            _ => None,
                                        })
                                        .unwrap_or_default();
                                    let value_bytes = any_msg
                                        .get_field_by_name("value")
                                        .map(|v| v.into_owned())
                                        .and_then(|v| match v {
                                            Value::Bytes(b) => Some(b),
                                            _ => None,
                                        });
                                    root.children.push(any_fallback_node(
                                        &type_url,
                                        &reason,
                                        value_bytes.as_deref().unwrap_or(&[]),
                                    ));
                                    continue;
                                }
                            }
                        }
                    }
                }
            }
            root.children.push(self.field_to_node(&field, &value, None));
        }
        let summary = summarize(&root, &any_type);
        WrapperResult {
            outer_type: short.to_string(),
            any_type,
            tree: Some(root),
            summary,
        }
    }

    /// google.protobuf.Any → 按 type_url 找消息递归解码。
    /// 失败时返回 Err(原因)，调用方用裸解码兜底展示。
    fn unpack_any(&self, any: &DynamicMessage) -> Result<(String, ProtoFieldNode), String> {
        let type_url = match any.get_field_by_name("type_url").map(|v| v.into_owned()) {
            Some(Value::String(s)) => s,
            _ => return Err("Any 缺少 type_url 字段".into()),
        };
        let value = match any.get_field_by_name("value").map(|v| v.into_owned()) {
            Some(Value::Bytes(b)) => b,
            _ => return Err("Any 缺少 value 字段".into()),
        };
        // "type.googleapis.com/pb.cds.business.IoConfigList" → "pb.cds.business.IoConfigList"
        // 兼容任意前缀：取最后一个 '/' 之后的部分
        let full_name = type_url
            .rsplit('/')
            .next()
            .unwrap_or(&type_url)
            .to_string();
        let short = full_name.rsplit('.').next().unwrap_or(&full_name).to_string();
        let desc = self
            .pool
            .get_message_by_name(&full_name)
            .or_else(|| {
                // 兜底：按短名在包内搜索（包名不一致时仍可解析）
                self.pool.all_messages().find(|m| m.name() == short)
            })
            .ok_or_else(|| {
                format!(
                    "proto 目录中找不到消息「{full_name}」（已加载 {} 个消息定义）",
                    self.pool.all_messages().count()
                )
            })?;
        let msg = DynamicMessage::decode(desc, value.as_ref())
            .map_err(|e| format!("消息「{full_name}」解码失败: {e}"))?;
        let node = self.message_to_node(short, &msg, None);
        Ok((full_name.rsplit('.').next().unwrap_or(&full_name).to_string(), node))
    }

    fn message_to_node(&self, name: String, msg: &DynamicMessage, _index: Option<usize>) -> ProtoFieldNode {
        let desc = msg.descriptor();
        let mut node = message_node(name, desc.name(), desc.full_name());
        // pb.common.Timestamp 特殊显示：转 1970 基准的本地时间（kind=timestamp 前端高亮渲染）
        if desc.full_name() == "pb.common.Timestamp" {
            let seconds = msg
                .get_field_by_name("seconds")
                .map(|v| v.into_owned())
                .and_then(|v| scalar_number(&v))
                .unwrap_or(0.0) as i64;
            let nanos = msg
                .get_field_by_name("nanos")
                .map(|v| v.into_owned())
                .and_then(|v| scalar_number(&v))
                .unwrap_or(0.0) as u32;
            node.kind = "timestamp".into();
            node.value_label = fmt_local_ts(seconds, nanos);
        }
        for (field, value) in iter_fields(msg) {
            node.children.push(self.field_to_node(&field, &value, None));
        }
        node
    }

    fn field_to_node(
        &self,
        field: &FieldDescriptor,
        value: &Value,
        index: Option<usize>,
    ) -> ProtoFieldNode {
        if field.is_list() {
            if let Value::List(items) = value {
                let mut node = ProtoFieldNode {
                    name: field.name().to_string(),
                    kind: "repeated".into(),
                    type_name: kind_name(field.kind()),
                    value_label: format!("[{}]", items.len()),
                    numeric: Some(items.len() as f64),
                    hex: None,
                    hex_total: None,
                    index,
                    children: Vec::new(),
                };
                for (i, item) in items.iter().enumerate() {
                    node.children.push(self.element_to_node(field, item, Some(i)));
                }
                return node;
            }
        }
        if field.is_map() {
            if let Value::Map(entries) = value {
                let mut node = ProtoFieldNode {
                    name: field.name().to_string(),
                    kind: "map".into(),
                    type_name: kind_name(field.kind()),
                    value_label: format!("[{}]", entries.len()),
                    numeric: Some(entries.len() as f64),
                    hex: None,
                    hex_total: None,
                    index,
                    children: Vec::new(),
                };
                for (i, (k, v)) in entries.iter().enumerate() {
                    let mut child = self.element_to_node(field, v, Some(i));
                    child.name = format!("{} → {}", map_key_to_string(k), child.name);
                    node.children.push(child);
                }
                return node;
            }
        }
        self.element_to_node(field, value, index)
    }

    /// 单个元素（非容器）：标量 / enum / message / bytes
    fn element_to_node(
        &self,
        field: &FieldDescriptor,
        value: &Value,
        index: Option<usize>,
    ) -> ProtoFieldNode {
        let name = field.name().to_string();
        match value {
            Value::Message(m) => self.message_to_node(name, m, index),
            Value::EnumNumber(n) => {
                let name_label = match field.kind() {
                    Kind::Enum(e) => e.get_value(*n).map(|v| v.name().to_string()),
                    _ => None,
                };
                let label = match name_label {
                    Some(en) => format!("{en} ({n})"),
                    None => format!("{n}"),
                };
                ProtoFieldNode {
                    name,
                    kind: "enum".into(),
                    type_name: kind_name(field.kind()),
                    value_label: label,
                    numeric: Some(*n as f64),
                    hex: None,
                    hex_total: None,
                    index,
                    children: Vec::new(),
                }
            }
            Value::Bytes(b) => {
                let total = b.len();
                let show: Vec<u8> = b.as_ref().iter().copied().take(MAX_HEX_BYTES).collect();
                ProtoFieldNode {
                    name,
                    kind: "bytes".into(),
                    type_name: "bytes".into(),
                    value_label: format!("{total} bytes"),
                    numeric: Some(total as f64),
                    hex: Some(hex_string(&show)),
                    hex_total: Some(total),
                    index,
                    children: Vec::new(),
                }
            }
            v => {
                let label = value_to_string(v);
                let numeric = scalar_number(v);
                ProtoFieldNode {
                    name,
                    kind: "scalar".into(),
                    type_name: kind_name(field.kind()),
                    value_label: label,
                    numeric,
                    hex: None,
                    hex_total: None,
                    index,
                    children: Vec::new(),
                }
            }
        }
    }
}

const MAX_HEX_BYTES: usize = 4096;

/// 遍历字段：全部显示（含 proto3 默认值 0 等，用户要求补全）
fn iter_fields(msg: &DynamicMessage) -> Vec<(FieldDescriptor, Value)> {
    msg.descriptor()
        .fields()
        .map(|f| (f.clone(), msg.get_field(&f).into_owned()))
        .collect()
}

fn is_implicit_default(field: &FieldDescriptor, v: &Value) -> bool {
    if field.is_list() || field.is_map() {
        // 空列表/空 map 跳过
        return matches!(v, Value::List(l) if l.is_empty()) || matches!(v, Value::Map(m) if m.is_empty());
    }
    if matches!(v, Value::Message(_)) {
        return false;
    }
    is_default_value(v)
}

pub struct WrapperResult {
    pub outer_type: String,
    pub any_type: String,
    pub tree: Option<ProtoFieldNode>,
    pub summary: String,
}

impl WrapperResult {
    fn raw(payload: &[u8]) -> Self {
        let show: Vec<u8> = payload.iter().copied().take(MAX_HEX_BYTES).collect();
        WrapperResult {
            outer_type: "?(raw)".into(),
            any_type: String::new(),
            tree: Some(ProtoFieldNode {
                name: "payload".into(),
                kind: "bytes".into(),
                type_name: "unknown".into(),
                value_label: format!("{} bytes (未识别外层结构)", payload.len()),
                numeric: Some(payload.len() as f64),
                hex: Some(hex_string(&show)),
                hex_total: Some(payload.len()),
                index: None,
                children: Vec::new(),
            }),
            summary: format!("{} bytes", payload.len()),
        }
    }
}

fn message_node(name: impl Into<String>, short: impl Into<String>, full: impl Into<String>) -> ProtoFieldNode {
    ProtoFieldNode {
        name: name.into(),
        kind: "message".into(),
        type_name: full.into(),
        value_label: short.into(),
        numeric: None,
        hex: None,
        hex_total: None,
        index: None,
        children: Vec::new(),
    }
}

/// Any 解包失败时的兜底节点：显示 type_url + 裸 wire-format 解码
fn any_fallback_node(type_url: &str, reason: &str, value: &[u8]) -> ProtoFieldNode {
    let mut children = Vec::new();
    children.push(ProtoFieldNode {
        name: "type_url".into(),
        kind: "scalar".into(),
        type_name: "string".into(),
        value_label: if type_url.is_empty() { "(空)".into() } else { type_url.to_string() },
        numeric: None,
        hex: None,
        hex_total: None,
        index: None,
        children: Vec::new(),
    });
    let raw = raw_decode_fields(value, 0);
    if !raw.is_empty() {
        children.push(ProtoFieldNode {
            name: "value (裸解码)".into(),
            kind: "message".into(),
            type_name: format!("{} bytes, 未识别的 proto 定义", value.len()),
            value_label: String::new(),
            numeric: None,
            hex: None,
            hex_total: None,
            index: None,
            children: raw,
        });
    } else if !value.is_empty() {
        let show: Vec<u8> = value.iter().copied().take(MAX_HEX_BYTES).collect();
        children.push(ProtoFieldNode {
            name: "value".into(),
            kind: "bytes".into(),
            type_name: "bytes".into(),
            value_label: format!("{} bytes", value.len()),
            numeric: Some(value.len() as f64),
            hex: Some(hex_string(&show)),
            hex_total: Some(value.len()),
            index: None,
            children: Vec::new(),
        });
    }
    ProtoFieldNode {
        name: "data".into(),
        kind: "error".into(),
        type_name: "google.protobuf.Any".into(),
        value_label: reason.to_string(),
        numeric: None,
        hex: None,
        hex_total: None,
        index: None,
        children,
    }
}

/// 无 descriptor 的 protobuf 裸解码：遍历 wire format 字段。
/// LEN 字段启发式判定：嵌套消息 / UTF-8 字符串 / hex。
pub fn raw_decode_fields(data: &[u8], depth: usize) -> Vec<ProtoFieldNode> {
    let mut out = Vec::new();
    let mut r = 0usize;
    while r < data.len() {
        let Some((tag, n)) = read_varint(&data[r..]) else { break };
        r += n;
        let field_num = tag >> 3;
        let wt = tag & 7;
        let name = format!("field_{field_num}");
        match wt {
            0 => {
                let Some((v, n)) = read_varint(&data[r..]) else { break };
                r += n;
                out.push(ProtoFieldNode {
                    name,
                    kind: "scalar".into(),
                    type_name: "varint".into(),
                    value_label: format!("{v} (0x{v:x})"),
                    numeric: Some(v as f64),
                    hex: None,
                    hex_total: None,
                    index: None,
                    children: Vec::new(),
                });
            }
            1 => {
                if r + 8 > data.len() { break }
                let b = &data[r..r + 8];
                r += 8;
                let f = f64::from_le_bytes(b.try_into().unwrap());
                let i = i64::from_le_bytes(b.try_into().unwrap());
                out.push(simple_node(name, "fixed64", format!("{i} / {f}")));
            }
            5 => {
                if r + 4 > data.len() { break }
                let b = &data[r..r + 4];
                r += 4;
                let f = f32::from_le_bytes(b.try_into().unwrap());
                let i = i32::from_le_bytes(b.try_into().unwrap());
                out.push(simple_node(name, "fixed32", format!("{i} / {f}")));
            }
            2 => {
                let Some((len, n)) = read_varint(&data[r..]) else { break };
                r += n;
                let len = len as usize;
                if r + len > data.len() { break }
                let b = &data[r..r + len];
                r += len;
                out.push(len_node(name, b, depth));
            }
            _ => break, // 3/4 (group) 已废弃，未知 wire type 无法继续
        }
    }
    out
}

fn simple_node(name: String, type_name: &str, label: String) -> ProtoFieldNode {
    ProtoFieldNode {
        name,
        kind: "scalar".into(),
        type_name: type_name.into(),
        value_label: label,
        numeric: None,
        hex: None,
        hex_total: None,
        index: None,
        children: Vec::new(),
    }
}

/// LEN 字段的启发式解码：嵌套消息 → 字符串 → hex
fn len_node(name: String, b: &[u8], depth: usize) -> ProtoFieldNode {
    let total = b.len();
    // 1) 尝试嵌套消息（深度限制，且必须完整消耗）
    if depth < 8 && total > 0 {
        let children = raw_decode_fields(b, depth + 1);
        let consumed_ok = !children.is_empty();
        if consumed_ok {
            // 验证是否恰好完整解析（重放检查消耗量）
            if raw_consumes_fully(b) {
                return ProtoFieldNode {
                    name,
                    kind: "message".into(),
                    type_name: "(未知消息, 裸解码)".into(),
                    value_label: format!("{{{} 字段}}", children.len()),
                    numeric: None,
                    hex: None,
                    hex_total: None,
                    index: None,
                    children,
                };
            }
        }
    }
    // 2) UTF-8 字符串
    if let Ok(s) = std::str::from_utf8(b) {
        if !s.is_empty() && s.chars().all(|c| !c.is_control() || c == '\n' || c == '\t') {
            return ProtoFieldNode {
                name,
                kind: "scalar".into(),
                type_name: "string".into(),
                value_label: s.to_string(),
                numeric: None,
                hex: None,
                hex_total: None,
                index: None,
                children: Vec::new(),
            };
        }
    }
    // 3) hex
    let show: Vec<u8> = b.iter().copied().take(MAX_HEX_BYTES).collect();
    ProtoFieldNode {
        name,
        kind: "bytes".into(),
        type_name: "bytes".into(),
        value_label: format!("{total} bytes"),
        numeric: Some(total as f64),
        hex: Some(hex_string(&show)),
        hex_total: Some(total),
        index: None,
        children: Vec::new(),
    }
}

/// 检查裸解码是否恰好消耗全部字节（判定嵌套消息的依据）
fn raw_consumes_fully(data: &[u8]) -> bool {
    let mut r = 0usize;
    while r < data.len() {
        let Some((tag, n)) = read_varint(&data[r..]) else { return false };
        r += n;
        if tag >> 3 == 0 {
            return false; // 字段号 0 非法
        }
        match tag & 7 {
            0 => {
                let Some((_, n)) = read_varint(&data[r..]) else { return false };
                r += n;
            }
            1 => r += 8,
            5 => r += 4,
            2 => {
                let Some((len, n)) = read_varint(&data[r..]) else { return false };
                r += n + len as usize;
            }
            _ => return false,
        }
        if r > data.len() {
            return false;
        }
    }
    r == data.len()
}

fn read_varint(data: &[u8]) -> Option<(u64, usize)> {
    let mut v: u64 = 0;
    let mut i = 0;
    loop {
        let b = *data.get(i)?;
        v |= ((b & 0x7f) as u64) << (i * 7);
        if b & 0x80 == 0 {
            return Some((v, i + 1));
        }
        i += 1;
        if i > 10 {
            return None;
        }
    }
}

/// 外层 wrapper 的结构校验：防错位（如把 RespData 塞进 PubData）
fn wrapper_structure_matches(msg: &DynamicMessage, desc: &MessageDescriptor) -> bool {
    let expected: &[&str] = match desc.full_name() {
        "pb.common.Pub" | "pb.common.Req" => &["packet_head"],
        "pb.common.PubData" | "pb.common.ReqData" => &["packet_head", "data"],
        "pb.common.Resp" => &["packet_head", "status"],
        "pb.common.RespData" => &["packet_head", "status", "data"],
        _ => return true,
    };
    for field in desc.fields() {
        if !expected.iter().any(|n| *n == field.name()) {
            let value = msg.get_field(&field).into_owned();
            if !is_implicit_default(&field, &value) {
                return false;
            }
        }
    }
    true
}

fn kind_name(kind: Kind) -> String {
    match kind {
        Kind::Message(m) => m.full_name().to_string(),
        Kind::Enum(e) => e.full_name().to_string(),
        k => kind_primitive_name(&k).to_string(),
    }
}

fn kind_primitive_name(kind: &Kind) -> &'static str {
    match kind {
        Kind::Double => "double",
        Kind::Float => "float",
        Kind::Int32 => "int32",
        Kind::Int64 => "int64",
        Kind::Uint32 => "uint32",
        Kind::Uint64 => "uint64",
        Kind::Sint32 => "sint32",
        Kind::Sint64 => "sint64",
        Kind::Fixed32 => "fixed32",
        Kind::Fixed64 => "fixed64",
        Kind::Sfixed32 => "sfixed32",
        Kind::Sfixed64 => "sfixed64",
        Kind::Bool => "bool",
        Kind::String => "string",
        Kind::Bytes => "bytes",
        _ => "unknown",
    }
}

fn map_key_to_string(k: &MapKey) -> String {
    match k {
        MapKey::Bool(b) => b.to_string(),
        MapKey::I32(i) => i.to_string(),
        MapKey::I64(i) => i.to_string(),
        MapKey::U32(i) => i.to_string(),
        MapKey::U64(i) => i.to_string(),
        MapKey::String(s) => s.clone(),
    }
}

/// Value → 显示字符串
fn value_to_string(v: &Value) -> String {
    match v {
        Value::I32(x) => x.to_string(),
        Value::I64(x) => x.to_string(),
        Value::U32(x) => x.to_string(),
        Value::U64(x) => x.to_string(),
        Value::F32(x) => fmt_float(*x as f64),
        Value::F64(x) => fmt_float(*x),
        Value::Bool(b) => b.to_string(),
        Value::String(s) => s.clone(),
        Value::Bytes(_) => "bytes".into(),
        Value::EnumNumber(n) => n.to_string(),
        Value::Message(m) => format!("{} {{…}}", m.descriptor().name()),
        Value::List(l) => format!("[{}]", l.len()),
        Value::Map(m) => format!("{{{}}}", m.len()),
    }
}

fn fmt_float(f: f64) -> String {
    if f == f.trunc() && f.abs() < 1e15 {
        format!("{f:.1}")
    } else {
        format!("{f}")
    }
}

fn scalar_number(v: &Value) -> Option<f64> {
    match v {
        Value::I32(i) => Some(*i as f64),
        Value::I64(i) => Some(*i as f64),
        Value::U32(i) => Some(*i as f64),
        Value::U64(i) => Some(*i as f64),
        Value::F32(f) => Some(*f as f64),
        Value::F64(f) => Some(*f),
        Value::EnumNumber(n) => Some(*n as f64),
        Value::Bool(b) => Some(*b as i32 as f64),
        _ => None,
    }
}

fn is_default_value(v: &Value) -> bool {
    match v {
        Value::Message(_) | Value::List(_) | Value::Map(_) => false,
        Value::String(s) => s.is_empty(),
        Value::Bytes(b) => b.is_empty(),
        Value::Bool(b) => !*b,
        Value::I32(i) => *i == 0,
        Value::I64(i) => *i == 0,
        Value::U32(i) => *i == 0,
        Value::U64(i) => *i == 0,
        Value::F32(f) => *f == 0.0,
        Value::F64(f) => *f == 0.0,
        Value::EnumNumber(n) => *n == 0,
    }
}

fn hex_string(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 3);
    for (i, b) in data.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// 生成首层摘要
fn summarize(root: &ProtoFieldNode, any_type: &str) -> String {
    let mut parts = Vec::new();
    if !any_type.is_empty() {
        parts.push(any_type.to_string());
    }
    for child in &root.children {
        if child.name == "status" {
            for f in &child.children {
                if f.name == "message" && !f.value_label.is_empty() {
                    parts.push(format!("status={}", f.value_label));
                }
            }
        }
    }
    parts.join(" · ")
}

/// epoch 秒/纳秒 → 本地时区时间字符串（1970.1.1 基准）
pub fn fmt_local_ts(seconds: i64, nanos: u32) -> String {
    use chrono::TimeZone;
    match chrono::Utc.timestamp_opt(seconds, nanos).single() {
        Some(dt) => dt
            .with_timezone(&chrono::Local)
            .format("%Y-%m-%d %H:%M:%S%.6f")
            .to_string(),
        None => format!("{seconds}s {nanos}ns"),
    }
}

fn collect_proto_files(dir: &Path) -> std::io::Result<Vec<std::path::PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(d)? {
            let entry = entry?;
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().and_then(|e| e.to_str()) == Some("proto") {
                out.push(p);
            }
        }
    }
    Ok(out)
}
