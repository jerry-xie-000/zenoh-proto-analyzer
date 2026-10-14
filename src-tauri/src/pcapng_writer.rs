//! pcapng 文件写入（小端）：SHB + IDB(以太网, 1µs 时间分辨率) + EPB 序列。
//! 供实时捕获保存会话，Wireshark 可直接打开。

use std::fs::File;
use std::io::{BufWriter, Write};

pub struct PcapNgWriter {
    file: BufWriter<File>,
    frames: u64,
}

fn block(body: &[u8], block_type: u32) -> Vec<u8> {
    // total = type(4) + len(4) + body + len(4)，body 需 4 字节对齐（调用方保证）
    let total = 8 + body.len() + 4;
    let mut b = Vec::with_capacity(total);
    b.extend_from_slice(&block_type.to_le_bytes());
    b.extend_from_slice(&(total as u32).to_le_bytes());
    b.extend_from_slice(body);
    b.extend_from_slice(&(total as u32).to_le_bytes());
    b
}

impl PcapNgWriter {
    pub fn create(path: &str) -> std::io::Result<Self> {
        let mut file = BufWriter::new(File::create(path)?);

        // Section Header Block
        let shb_body = {
            let mut b = Vec::new();
            b.extend_from_slice(&0x1A2B3C4Du32.to_le_bytes()); // byte-order magic
            b.extend_from_slice(&1u16.to_le_bytes()); // major
            b.extend_from_slice(&0u16.to_le_bytes()); // minor
            b.extend_from_slice(&u64::MAX.to_le_bytes()); // section length: unspecified
            b
        };
        file.write_all(&block(&shb_body, 0x0A0D0D0A))?;

        // Interface Description Block: linktype=1 (Ethernet), snaplen=65535,
        // option if_tsresol(9)=6 → 时间戳单位 1µs
        let idb_body = {
            let mut b = Vec::new();
            b.extend_from_slice(&1u16.to_le_bytes()); // linktype
            b.extend_from_slice(&0u16.to_le_bytes()); // reserved
            b.extend_from_slice(&0xFFFFu32.to_le_bytes()); // snaplen
            // option: code=9, len=1, value=6, pad 3
            b.extend_from_slice(&9u16.to_le_bytes());
            b.extend_from_slice(&1u16.to_le_bytes());
            b.extend_from_slice(&[6, 0, 0, 0]);
            // opt_endofopt
            b.extend_from_slice(&0u16.to_le_bytes());
            b.extend_from_slice(&0u16.to_le_bytes());
            b
        };
        file.write_all(&block(&idb_body, 0x00000001))?;

        Ok(Self {
            file,
            frames: 0,
        })
    }

    /// 写入一帧（以太网帧），ts_us 为 Unix 微秒
    pub fn write_frame(&mut self, ts_us: i64, data: &[u8]) -> std::io::Result<()> {
        let pad = (4 - (data.len() % 4)) % 4;
        let ts = ts_us.max(0) as u64;
        let mut body = Vec::with_capacity(16 + data.len() + pad);
        body.extend_from_slice(&0u32.to_le_bytes()); // interface id
        body.extend_from_slice(&((ts >> 32) as u32).to_le_bytes());
        body.extend_from_slice(&((ts & 0xFFFF_FFFF) as u32).to_le_bytes());
        body.extend_from_slice(&(data.len() as u32).to_le_bytes()); // captured len
        body.extend_from_slice(&(data.len() as u32).to_le_bytes()); // original len
        body.extend_from_slice(data);
        body.extend(std::iter::repeat(0u8).take(pad));
        self.file.write_all(&block(&body, 0x00000006))?;
        self.frames += 1;
        Ok(())
    }

    pub fn frames(&self) -> u64 {
        self.frames
    }

    pub fn finish(mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}
