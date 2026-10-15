//! 调试 181807 文件的重组与解析
use app_lib::reassembly::{FlowKey, StreamAssembler};
use app_lib::source;

#[test]
fn debug_reassembly() {
    let frames = source::read_file("../../测试用例/zenoh-capture-20261014-181807.pcapng").unwrap();
    println!("总帧数: {}", frames.len());
    let mut assembler = StreamAssembler::new();
    let mut frame_ts = std::collections::HashMap::new();
    for (i, f) in frames.iter().enumerate() {
        frame_ts.insert((i + 1) as u32, f.ts_us);
        if let Some(seg) = app_lib::pipeline::parse_tcp_frame(&f.data) {
            assembler.add_segment(
                FlowKey { src: format!("{}:{}", seg.src_ip, seg.src_port), dst: format!("{}:{}", seg.dst_ip, seg.dst_port) },
                seg.seq, &seg.payload, (i + 1) as u32,
            );
        }
    }
    let streams = assembler.finish();
    for (key, stream) in &streams {
        println!("流 {} → {} : {} 字节", key.src, key.dst, stream.data.len());
    }
    // 解析
    let mut sessions = app_lib::zenoh::Sessions::new();
    let mut total = 0usize;
    for (key, stream) in streams {
        let (a, b) = app_lib::pipeline::normalize_session(&key.src, &key.dst);
        let is_a = key.src == a;
        let frame_at = |off: usize| stream.frame_at(off);
        let ts_at = |f: u32| frame_ts.get(&f).copied().unwrap_or(0);
        let msgs = app_lib::zenoh::parse_stream(
            &stream.data, frame_at, ts_at, (a.clone(), b.clone()), is_a, &mut sessions,
        );
        println!("流 {} → {} 消息", key.src, msgs.len());
        total += msgs.len();
    }
    println!("总消息: {total}");
}
