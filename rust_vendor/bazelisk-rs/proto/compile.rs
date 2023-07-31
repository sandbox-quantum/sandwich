// Copyright 2023 SandboxAQ
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Compiles protobuf definitions.

extern crate protobuf_codegen;
extern crate protoc_bin_vendored;

/// Joins a path with the `OUT_DIR` directory.
fn out_dir(p: impl std::convert::AsRef<std::path::Path>) -> Result<std::path::PathBuf, String> {
    Ok(std::path::PathBuf::from(
        std::env::var("OUT_DIR").map_err(|e| format!("`OUT_DIR` cannot be read: {e}"))?,
    )
    .join(p))
}

/// Creates an intermediate directory under the `OUT_DIR` directory.
fn new_out_dir(p: impl std::convert::AsRef<std::path::Path>) -> Result<(), String> {
    let out_dir = std::path::PathBuf::from(
        std::env::var("OUT_DIR").map_err(|e| format!("`OUT_DIR` cannot be read: {e}"))?,
    );
    std::fs::DirBuilder::new()
        .recursive(true)
        .create(out_dir.join(p.as_ref()))
        .map_err(|e| {
            format!(
                "failed to create a subdirectory called {} in the `OUT_DIR` directory: {e}",
                p.as_ref().to_string_lossy()
            )
        })
}

/// Removes the `#!` part of a generated file, and the `//!`.
fn sanitize_file(
    input: impl std::convert::AsRef<std::path::Path>,
    output: impl std::convert::AsRef<std::path::Path>,
) -> Result<(), String> {
    let reader = std::io::BufReader::new(
        std::fs::File::open(input.as_ref())
            .map_err(|e| format!("failed to open {}: {e}", input.as_ref().to_string_lossy()))?,
    );

    let mut writer = std::io::BufWriter::new(
        std::fs::File::options()
            .create(true)
            .read(false)
            .write(true)
            .truncate(true)
            .open(output.as_ref())
            .map_err(|e| format!("cannot open {}: {e}", output.as_ref().to_string_lossy()))?,
    );

    for l in <_ as std::io::BufRead>::lines(reader) {
        let l = l.map_err(|e| format!("failed to read line: {e}"))?;
        if !l.starts_with("#![") && !l.starts_with("//!") {
            <_ as std::io::Write>::write_all(&mut writer, l.as_bytes())
                .map_err(|e| format!("cannot write line: {e}"))?;
            <_ as std::io::Write>::write_all(&mut writer, &[b'\n'])
                .map_err(|e| format!("cannot write end of line: {e}"))?;
        }
    }

    Ok(())
}

fn main() {
    new_out_dir("proto").expect("cannot create intermediate directory");
    new_out_dir("bazelisk-proto").expect("cannot create intermediate directory");
    protobuf_codegen::Codegen::new()
        .protoc()
        .protoc_path(&protoc_bin_vendored::protoc_bin_path().unwrap())
        .includes([".", "src/main/protobuf/build.proto=build.proto"])
        .input("analysis_v2.proto")
        .cargo_out_dir("proto")
        .customize(protobuf_codegen::Customize::default().gen_mod_rs(false))
        .run_from_script();
    sanitize_file(
        out_dir("proto/analysis_v2.rs").unwrap(),
        out_dir("bazelisk-proto/analysis_v2.rs").unwrap(),
    )
    .expect("failed to sanitize the file");
    protobuf_codegen::Codegen::new()
        .protoc()
        .protoc_path(&protoc_bin_vendored::protoc_bin_path().unwrap())
        .includes([".", "src/main/protobuf/build.proto=build.proto"])
        .input("build.proto")
        .cargo_out_dir("proto/")
        .customize(protobuf_codegen::Customize::default().gen_mod_rs(false))
        .run_from_script();
    sanitize_file(
        out_dir("proto/build.rs").unwrap(),
        out_dir("bazelisk-proto/build.rs").unwrap(),
    )
    .expect("failed to sanitize the file");
}
