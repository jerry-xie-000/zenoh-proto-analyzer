//! 与前端对齐的数据模型。

use serde::{Deserialize, Serialize};

use crate::protobuf::ProtoFieldNode;

/// 表格行摘要（一次解析全部返回，详情懒加载）
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PacketRow {
    /// 消息序号（0 起，按出现顺序）
    pub index: usize,
    /// 所在 pcap 帧号（1 起）
    pub frame_number: u32,
    /// 关联的全部帧号（TCP 分段 batch 跨多帧）
    pub frame_numbers: Vec<u32>,
    /// 绝对时间戳（微秒，Unix epoch）
    pub ts_us: i64,
    /// 相对首个 Zenoh 消息的时间（微秒，可为负/0）
    pub rel_us: i64,
    /// 源 "ip:port"
    pub src: String,
    /// 目的 "ip:port"
    pub dst: String,
    /// 方向描述："→设备" / "→服务器"
    pub direction: String,
    /// Zenoh 消息类型："Push(Put)" / "Request(Query)" / "Response(Reply)" / "Declare(KeyExpr)" …
    pub msg_type: String,
    /// 完整 topic（mapping 未知时为 "~id/suffix" 形式）
    pub topic: String,
    /// topic 是否完整（false = mapping 缺失，中途加入捕获）
    pub topic_complete: bool,
    /// 外层 protobuf 类型："PubData" / "ReqData" / …；未解析出为 "?(raw)"
    pub outer_type: String,
    /// Any 目标业务类型："IoConfigList"；无 Any 则为空
    pub any_type: String,
    /// PacketHead.device_id（多设备调试用）
    pub device_id: String,
    /// 首层摘要
    pub summary: String,
    /// Request/Response 的 id（配对用）
    pub rid: Option<u32>,
    /// 配对消息的 index
    pub pair_index: Option<usize>,
    /// 往返耗时（毫秒），仅 Response 侧填
    pub rtt_ms: Option<f64>,
    /// payload 长度（字节）
    pub payload_len: usize,
    /// 解析警告（如 mapping 缺失、外层类型不确定）
    pub warnings: Vec<String>,
}

/// zenoh 层键值
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Kv {
    pub key: String,
    pub value: String,
}

/// 详情（懒加载）
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DetailData {
    /// zenoh 层字段
    pub zenoh_fields: Vec<Kv>,
    /// protobuf 树
    pub proto_tree: Option<ProtoFieldNode>,
    /// payload hex（每行 "00000000  xx xx ..  ascii"）
    pub hex_lines: Vec<String>,
}

/// 统计
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Stats {
    pub total: usize,
    /// 消息类型 → 数量
    pub by_type: Vec<(String, usize)>,
    /// topic → 数量（按数量降序）
    pub by_topic: Vec<(String, usize)>,
    /// Topic 帧率（msg/s，按速率降序）
    pub topic_rates: Vec<(String, f64)>,
    /// get/set 查询的内部类型帧率（"topic → 内部类型" → msg/s，按速率降序）
    pub query_type_rates: Vec<(String, f64)>,
    /// 设备 id 集合（PacketHead.device_id）
    pub devices: Vec<String>,
    /// 时间范围（微秒）
    pub ts_first: Option<i64>,
    pub ts_last: Option<i64>,
    /// 会话信息
    pub sessions: Vec<String>,
}

/// 解析整体结果
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ParseResult {
    pub rows: Vec<PacketRow>,
    /// 会话/解析级别的警告
    pub warnings: Vec<String>,
}

/// 网卡接口信息
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InterfaceInfo {
    pub name: String,
    pub desc: String,
    /// Windows 连接别名（如 "以太网"、"WLAN"）
    pub alias: String,
    pub addresses: Vec<String>,
}
