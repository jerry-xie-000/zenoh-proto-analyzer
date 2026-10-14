//! TCP 流重组：按五元组分流，seq 排序去重，拼成有序字节流。
//! 记录每个字节区间所属帧号，用于行级时间/帧号展示。
//!
//! 乱序处理：先收集全部段（保留原始 seq），重组时以最小 seq 为基准相对化，
//! 避免"首段乱序在后"导致基准选错而整体错位。

use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FlowKey {
    pub src: String,
    pub dst: String,
}

#[derive(Debug, Clone)]
pub struct ByteStream {
    pub data: Vec<u8>,
    /// (字节偏移, 帧号) 区间映射：offset 落在哪个区间就用哪个帧号
    pub frame_map: Vec<(usize, u32)>,
}

impl ByteStream {
    /// 查询 offset 所属帧号（二分）
    pub fn frame_at(&self, offset: usize) -> u32 {
        let map = &self.frame_map;
        match map.binary_search_by_key(&offset, |&(o, _)| o) {
            Ok(i) => map[i].1,
            Err(0) => map.first().map(|&(_, f)| f).unwrap_or(0),
            Err(i) => map[i - 1].1,
        }
    }
}

type Segment = (u32 /*raw seq*/, Vec<u8>, u32 /*frame*/);

#[derive(Default)]
pub struct StreamAssembler {
    flows: HashMap<FlowKey, Vec<Segment>>,
}

impl StreamAssembler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_segment(&mut self, key: FlowKey, seq: u32, data: &[u8], frame: u32) {
        if data.is_empty() {
            return;
        }
        self.flows.entry(key).or_default().push((seq, data.to_vec(), frame));
    }

    /// 完成重组，输出每条流的有序字节流
    pub fn finish(mut self) -> HashMap<FlowKey, ByteStream> {
        let mut out = HashMap::new();
        for (key, mut segs) in self.flows.drain() {
            // 以最小 raw seq 为基准（流的真实起点），相对化后排序。
            // 同 seq 冲突时优先更长的段：过滤掉 keepalive 探测包
            // （其 seq 与真实数据段相同、内容为垃圾零字节、长度很短）
            let base = segs.iter().map(|(s, _, _)| *s).min().unwrap_or(0);
            segs.sort_by(|a, b| {
                let ra = a.0.wrapping_sub(base);
                let rb = b.0.wrapping_sub(base);
                ra.cmp(&rb).then(b.1.len().cmp(&a.1.len()))
            });
            let mut data = Vec::new();
            let mut frame_map: Vec<(usize, u32)> = Vec::new();
            let mut covered: u64 = 0; // 已填充到的相对位置
            for (raw, buf, frame) in segs {
                let start = raw.wrapping_sub(base) as u64;
                let end = start + buf.len() as u64;
                if end <= covered {
                    continue; // 完全重复（重传/探测）
                }
                let skip = if start < covered { (covered - start) as usize } else { 0 };
                // 缺口（start > covered）：丢弃缺失段直接接上（无法恢复）
                frame_map.push((data.len(), frame));
                data.extend_from_slice(&buf[skip..]);
                covered = end;
            }
            frame_map.shrink_to_fit();
            out.insert(key, ByteStream { data, frame_map });
        }
        out
    }
}
