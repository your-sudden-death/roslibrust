use std::module_path;
use std::path::Path;

use log::*;
use simple_logger::SimpleLogger;

use roslibrust::message_gen;
use roslibrust::util;

/// Basic example of manually calling code generation
fn main() {
    SimpleLogger::new()
        .with_level(log::LevelFilter::Debug)
        .init()
        .unwrap();
    let source_path = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/test_msgs"));
    let dest_path = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src/gen_msgs.rs"));
    let files = util::recursive_find_msg_files(source_path);
    info!("Running on files: {:?}", files);

    message_gen::generate_messages(files.into_iter().map(|e| e.path).collect(), dest_path)
}
