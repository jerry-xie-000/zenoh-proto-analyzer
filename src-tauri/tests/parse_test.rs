//! 端到端解析验证：跑真实 pcapng + proto 目录，对照 Wireshark 解析结果。

use app_lib::pipeline::parse_file;

#[test]
fn parse_real_pcapng() {
    let pcap = "../../测试用例/33333.pcapng";
    let proto = "../../测试用例/protobuf_define";
    let analyzer = match parse_file(pcap, Some(proto)) {
        Ok(a) => a,
        Err(e) => panic!("解析失败: {e}"),
    };

    println!("=== 总消息数: {} ===", analyzer.entries.len());
    println!("=== 统计 ===");
    for (t, n) in &analyzer.stats.by_type {
        println!("  {t}: {n}");
    }
    println!("=== Topic 分布 (前10) ===");
    for (t, n) in analyzer.stats.by_topic.iter().take(10) {
        println!("  {t}: {n}");
    }

    // 帧号 259 应该是 Push → cds/device/pub/business/io_config + IoConfigList
    if let Some(e) = analyzer.entries.iter().find(|e| e.row.frame_number == 259) {
        println!("\n=== frame 259 ===");
        println!("  type={} topic={}", e.row.msg_type, e.row.topic);
        println!("  outer={} any={}", e.row.outer_type, e.row.any_type);
        println!("  summary={}", e.row.summary);
        assert_eq!(e.row.msg_type, "Push(Put)");
        assert_eq!(e.row.topic, "cds/device/pub/business/io_config");
        assert_eq!(e.row.any_type, "IoConfigList");
    } else {
        panic!("没有解析到 frame 259");
    }

    // 至少解析出足量消息（Wireshark 里 zenoh 534 帧，其中含数据消息）
    assert!(
        analyzer.entries.len() > 400,
        "消息数过少: {}",
        analyzer.entries.len()
    );

    // 打印几条典型消息的树
    let mut shown = 0;
    for e in &analyzer.entries {
        if shown >= 3 {
            break;
        }
        if e.row.any_type.is_empty() {
            continue;
        }
        let detail = analyzer.detail(e.row.index).unwrap();
        println!("\n=== #{} {} {} ===", e.row.index, e.row.msg_type, e.row.topic);
        print_tree(detail.proto_tree.as_ref().unwrap(), 1);
        shown += 1;
    }
}

fn print_tree(node: &app_lib::protobuf::ProtoFieldNode, depth: usize) {
    let pad = "  ".repeat(depth);
    println!(
        "{pad}{} [{}] {} = {}",
        node.name, node.kind, node.type_name, node.value_label
    );
    for c in node.children.iter().take(if depth < 4 { usize::MAX } else { 2 }) {
        print_tree(c, depth + 1);
    }
    let hidden = node.children.len().saturating_sub(if depth < 4 { usize::MAX } else { 2 });
    if hidden > 0 {
        println!("{pad}  … 还有 {hidden} 项");
    }
}
