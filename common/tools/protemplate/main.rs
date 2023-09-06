//! Implementation of the protobuf plugin to generate a template given protobuf
//! metadata.

extern crate env_logger;
extern crate log;
extern crate metaproto;
extern crate protobuf;
extern crate serde;
extern crate tinytemplate;

use metaproto::symbol::Content;
use metaproto::MetaProto;
use protobuf::plugin::code_generator_response::File;
use protobuf::plugin::{CodeGeneratorRequest, CodeGeneratorResponse};
use protobuf::Message;
use tinytemplate::TinyTemplate;

use std::path::PathBuf;

/// Sends the response to stdout.
fn send_response(response: CodeGeneratorResponse) {
    let out: Vec<u8> = <_ as Message>::write_to_bytes(&response).unwrap();
    <_ as std::io::Write>::write_all(&mut std::io::stdout(), &out).unwrap();
}

/// Reports an error.
fn report_error(msg: String) -> ! {
    log::error!("{msg}");
    let mut response = CodeGeneratorResponse::new();
    response.set_error(msg.clone());
    send_response(response);
    std::process::exit(1);
}

/// Constructs a [`protobuf::plugin::CodeGeneratorRequest`] from stdin.
fn code_gen_request_from_stdin() -> Result<CodeGeneratorRequest, String> {
    use std::io::Read;

    let mut req = Vec::new();

    std::io::BufReader::new(std::io::stdin())
        .read_to_end(&mut req)
        .map_err(|e| format!("failed to read from stdin: {e}"))?;

    CodeGeneratorRequest::parse_from_bytes(&req)
        .map_err(|e| format!("failed to parse the code generator request from stdin: {e}"))
}

/// Reads and returns content of the template file.
fn read_template(req: &CodeGeneratorRequest) -> Result<String, String> {
    let template = req.parameter.as_deref().ok_or_else(|| {
        "parameter required: parameter must point to the template file".to_string()
    })?;
    std::fs::read(template)
        .map_err(|e| format!("failed to read {template}: {e}"))
        .and_then(|content| {
            String::from_utf8(content)
                .map_err(|e| format!("failed to read {template} as UTF-8: {e}"))
        })
}

/// An error value.
/// This comes from a enum's value.
#[derive(serde::Serialize)]
struct Value<'s> {
    /// Name.
    name: &'s str,

    /// Leading comment.
    leading_comment: &'s str,

    /// Trailing comment.
    trailing_comment: &'s str,
}

/// A symbol.
#[derive(serde::Serialize)]
struct Symbol<'s> {
    /// Name of the symbol.
    name: &'s str,

    /// Leading comment of the symbol.
    leading_comment: &'s str,

    /// Trailing comment of the symbol.
    trailing_comment: &'s str,

    /// Values in the symbol.
    values: Vec<Value<'s>>,
}

/// Context for tinytemplate.
#[derive(serde::Serialize)]
struct Context<'s> {
    /// Symbols.
    symbols: Vec<Symbol<'s>>,
}

fn main() {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Debug)
        .init();

    let req = code_gen_request_from_stdin()
        .map_err(|e| report_error(format!("failed to build the code generator request: {e}")))
        .unwrap();

    let template = read_template(&req).map_err(report_error).unwrap();

    let out_file_path = PathBuf::from(
        std::env::var("OUT_FILE_PATH")
            .map_err(|e| report_error(format!("failed to retrieve the out file path: {e}")))
            .unwrap(),
    );
    let out_file_basename = out_file_path
        .file_name()
        .ok_or_else(|| format!("{} does not have a file name", out_file_path.display()))
        .and_then(|s| {
            s.to_str().ok_or_else(|| {
                format!(
                    "{} cannot be converted into an UTF-8 string",
                    out_file_path.display()
                )
            })
        })
        .map_err(report_error)
        .unwrap();

    let handle = MetaProto::try_from(&req).map_err(report_error).unwrap();

    let mut context = Context {
        symbols: Vec::new(),
    };
    for sym in handle.symbols() {
        let e = if let Content::Enum(e) = sym.content() {
            e
        } else {
            log::warn!("skipping {}: not an enum", sym.info().name());
            continue;
        };
        let mut s = Symbol {
            name: sym.info().name(),
            leading_comment: sym
                .info()
                .comments()
                .and_then(|c| c.leading())
                .unwrap_or("")
                .trim(),
            trailing_comment: sym
                .info()
                .comments()
                .and_then(|c| c.trailing())
                .unwrap_or("")
                .trim(),
            values: Vec::new(),
        };

        for v in e.values() {
            s.values.push(Value {
                name: v.name(),
                leading_comment: v.comments().and_then(|c| c.leading()).unwrap_or("").trim(),
                trailing_comment: v.comments().and_then(|c| c.trailing()).unwrap_or("").trim(),
            });
        }
        context.symbols.push(s);
    }

    let mut tt = TinyTemplate::new();
    tt.add_template("template", template.as_str())
        .map_err(|e| report_error(format!("failed to initialize template: {e}")))
        .unwrap();
    let content = tt
        .render("template", &context)
        .map_err(|e| report_error(format!("failed to render: {e}")))
        .unwrap();

    let mut response = CodeGeneratorResponse::new();
    let mut out_file = File::new();
    out_file.set_name(out_file_basename.into());
    out_file.set_content(content);
    response.file.push(out_file);

    send_response(response);
}
