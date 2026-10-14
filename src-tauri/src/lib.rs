pub mod commands;
pub mod model;
pub mod pcapng_writer;
mod pipeline;
pub mod protobuf;
pub mod reassembly;
pub mod source;
pub mod zenoh;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(commands::AppState::default())
        .invoke_handler(tauri::generate_handler![
            commands::parse_pcap,
            commands::get_detail,
            commands::get_stats,
            commands::list_interfaces,
            commands::count_proto_files,
            commands::start_capture,
            commands::stop_capture,
        ])
        .setup(|app| {
            // 命令行参数自动打开：app.exe <pcap路径> <proto目录>
            let args: Vec<String> = std::env::args().skip(1).collect();
            if let (Some(pcap), Some(proto)) = (args.first(), args.get(1)) {
                let handle = app.handle().clone();
                let (pcap, proto) = (pcap.clone(), proto.clone());
                std::thread::spawn(move || {
                    std::thread::sleep(std::time::Duration::from_millis(1500));
                    use tauri::Emitter;
                    let _ = handle.emit("demo-open", (pcap, proto));
                });
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while building tauri application");
}
