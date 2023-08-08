//! Implementation of the protobuf plugin to generate markdown.
extern crate env_logger;
extern crate log;
extern crate metaproto;
extern crate protobuf;

mod template;

/// Sends the response to stdout.
fn send_response(response: protobuf::plugin::CodeGeneratorResponse) {
    let out: Vec<u8> = <_ as protobuf::Message>::write_to_bytes(&response).unwrap();
    <_ as std::io::Write>::write_all(&mut std::io::stdout(), &out).unwrap();
}

/// Reports an error.
fn report_error(msg: String) {
    log::error!("{msg}");
    let mut response = protobuf::plugin::CodeGeneratorResponse::new();
    response.set_error(msg.clone());
    send_response(response);
    panic!("{msg}");
}

/// Constructs a [`protobuf::plugin::CodeGeneratorRequest`] from stdin.
fn code_gen_request_from_stdin() -> Result<protobuf::plugin::CodeGeneratorRequest, String> {
    use std::io::Read;

    let mut req = Vec::new();

    std::io::BufReader::new(std::io::stdin())
        .read_to_end(&mut req)
        .map_err(|e| format!("failed to read from stdin: {e}"))?;

    <protobuf::plugin::CodeGeneratorRequest as protobuf::Message>::parse_from_bytes(&req)
        .map_err(|e| format!("failed to parse the code generator request from stdin: {e}"))
}

/// A file content.
pub struct FileContent {
    /// The actual content of the file.
    content: String,

    /// The filename.
    name: String,
}

fn main() {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Debug)
        .init();

    let req = code_gen_request_from_stdin()
        .map_err(|e| report_error(format!("failed to build the code generator request: {e}")))
        .unwrap();

    let handle = metaproto::MetaProto::try_from(&req)
        .map_err(|e| report_error(format!("failed to parse proto files: {e}")))
        .unwrap();

    let mut files = Vec::<FileContent>::new();

    for sym in handle.symbols() {
        let name = sym.info().name();
        let mut os = String::new();
        for s in sym.info().source() {
            os.push_str(s);
        }
        match sym.content() {
            metaproto::symbol::Content::Message(msg) => {
                log::debug!("Found message `{name}`");
                files.push(template::produce_message_content(sym, msg));
            }
            metaproto::symbol::Content::Enum(e) => {
                log::debug!("Found enum `{name}`");
                files.push(template::produce_enum_content(sym, e));
            }
        }
    }

    let mut response = protobuf::plugin::CodeGeneratorResponse::new();
    for file_content in files {
        let mut file = protobuf::plugin::code_generator_response::File::new();
        file.set_name(format!("{filename}.md", filename = file_content.name));
        file.set_content(file_content.content);
        response.file.push(file);
    }

    send_response(response);
}
