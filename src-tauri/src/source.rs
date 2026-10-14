//! 数据源：pcapng / 经典 pcap 文件读取。
//! 自写 block 解析，只依赖标准库。

use std::fs;

#[derive(Debug, Clone)]
pub struct Frame {
    /// 捕获时间戳（微秒，Unix epoch）
    pub ts_us: i64,
    /// 链路层数据（以太网帧）
    pub data: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    #[error("IO错误: {0}")]
    Io(#[from] std::io::Error),
    #[error("不是有效的 pcap/pcapng 文件")]
    BadMagic,
    #[error("pcapng block 解析错误: {0}")]
    BadBlock(String),
}

pub fn read_file(path: &str) -> Result<Vec<Frame>, SourceError> {
    let buf = fs::read(path)?;
    if buf.len() < 12 {
        return Err(SourceError::BadMagic);
    }
    // pcapng: SHB block-type 0x0A0D0D0A
    if buf[0..4] == [0x0a, 0x0d, 0x0d, 0x0a] {
        read_pcapng(&buf)
    } else {
        read_pcap(&buf)
    }
}

// ---------- pcapng ----------

fn read_pcapng(buf: &[u8]) -> Result<Vec<Frame>, SourceError> {
    // SHB 内的 byte-order magic 判断端序
    let little = &buf[8..12] == [0x4d, 0x3c, 0x2b, 0x1a];
    if !little && &buf[8..12] != [0x1a, 0x2b, 0x3c, 0x4d] {
        return Err(SourceError::BadMagic);
    }
    let rd = |b: &[u8], off: usize| -> u32 {
        if little {
            u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
        } else {
            u32::from_be_bytes(b[off..off + 4].try_into().unwrap())
        }
    };

    let mut frames = Vec::new();
    let mut linktype: u32 = 1; // 默认以太网
    let mut ts_resol_mult: f64 = 1.0; // 时间戳 → 微秒 的乘数，默认 if_tsresol=6 (1us)

    let mut off = 0usize;
    while off + 12 <= buf.len() {
        let btype = rd(buf, off);
        let total = rd(buf, off + 4) as usize;
        if total < 12 || off + total > buf.len() {
            return Err(SourceError::BadBlock(format!(
                "block 长度异常: type=0x{btype:08x} len={total}"
            )));
        }
        let body = &buf[off + 8..off + total - 4];

        match btype {
            0x0000_0001 => {
                // Interface Description Block: linktype(u16) + reserved(u16) + options
                if body.len() >= 4 {
                    linktype = if little {
                        u16::from_le_bytes(body[0..2].try_into().unwrap()) as u32
                    } else {
                        u16::from_be_bytes(body[0..2].try_into().unwrap()) as u32
                    };
                }
                // options: code(u16) len(u16) value…
                let mut o = 4usize;
                while o + 4 <= body.len() {
                    let (code, olen) = if little {
                        (
                            u16::from_le_bytes(body[o..o + 2].try_into().unwrap()),
                            u16::from_le_bytes(body[o + 2..o + 4].try_into().unwrap()),
                        )
                    } else {
                        (
                            u16::from_be_bytes(body[o..o + 2].try_into().unwrap()),
                            u16::from_be_bytes(body[o + 2..o + 4].try_into().unwrap()),
                        )
                    };
                    if code == 0 {
                        break;
                    }
                    if code == 9 && olen >= 1 {
                        // if_tsresol: 高4位=10^-n 或 2^n
                        let r = body[o + 4];
                        ts_resol_mult = if r & 0x80 == 0 {
                            10f64.powi(-(r as i32)) * 1e6
                        } else {
                            1.0 / (1u64 << (r & 0x7f)) as f64 * 1e6
                        };
                    }
                    // option 4 字节对齐
                    o += 4 + (olen as usize).div_ceil(4) * 4;
                }
            }
            0x0000_0006 => {
                // Enhanced Packet Block
                if body.len() >= 20 && linktype == 1 {
                    let caplen = rd(body, 12) as usize;
                    if caplen <= body.len() - 16 {
                        let ts = (rd(body, 4) as u64) << 32 | rd(body, 8) as u64;
                        frames.push(Frame {
                            ts_us: (ts as f64 * ts_resol_mult) as i64,
                            data: body[20..20 + caplen].to_vec(),
                        });
                    }
                }
            }
            _ => {}
        }
        off += total;
    }
    Ok(frames)
}

// ---------- 经典 pcap ----------

fn read_pcap(buf: &[u8]) -> Result<Vec<Frame>, SourceError> {
    let magic = &buf[0..4];
    let (little, nanos) = match magic {
        [0xd4, 0xc3, 0xb2, 0xa1] => (true, false),
        [0xa1, 0xb2, 0xc3, 0xd4] => (false, false),
        [0x4d, 0x3c, 0xb2, 0xa1] => (true, true),
        [0xa1, 0xb2, 0x3c, 0x4d] => (false, true),
        _ => return Err(SourceError::BadMagic),
    };
    let _rd16 = |b: &[u8], o: usize| -> u16 {
        if little {
            u16::from_le_bytes(b[o..o + 2].try_into().unwrap())
        } else {
            u16::from_be_bytes(b[o..o + 2].try_into().unwrap())
        }
    };
    let rd32 = |b: &[u8], o: usize| -> u32 {
        if little {
            u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
        } else {
            u32::from_be_bytes(b[o..o + 4].try_into().unwrap())
        }
    };

    let mut frames = Vec::new();
    let mut off = 24usize; // 全局头
    while off + 16 <= buf.len() {
        let ts_sec = rd32(buf, off) as i64;
        let ts_frac = rd32(buf, off + 4) as i64;
        let caplen = rd32(buf, off + 8) as usize;
        let _origlen = rd32(buf, off + 12) as usize;
        off += 16;
        if off + caplen > buf.len() {
            break;
        }
        let ts_us = if nanos { ts_sec * 1_000_000 + ts_frac / 1000 } else { ts_sec * 1_000_000 + ts_frac };
        frames.push(Frame { ts_us, data: buf[off..off + caplen].to_vec() });
        off += caplen;
    }
    Ok(frames)
}
