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

//! Support for reading the ActionGraph.
//!
//! ActionGraph is a structure defined in Bazel.
/// See <https://github.com/bazelbuild/bazel/blob/51aae5ffa42dd6da63f61949d402a81f178fb99e/src/main/protobuf/analysis_v2.proto>.
extern crate build_rust_proto;
extern crate protobuf;

/// A map mapping a path_fragment ID to a file path.
/// See <https://github.com/bazelbuild/bazel/blob/51aae5ffa42dd6da63f61949d402a81f178fb99e/src/main/protobuf/analysis_v2.proto#L239>.
type PathFragmentMap<'a> = std::collections::HashMap<u32, &'a build_rust_proto::PathFragment>;

/// Builds the map of path fragments from a `aquery` query output.
fn get_paths_fragments(
    agc: &'_ build_rust_proto::ActionGraphContainer,
) -> Result<PathFragmentMap<'_>, String> {
    let mut map = PathFragmentMap::with_capacity(agc.path_fragments.len());
    for fragment in agc.path_fragments.iter() {
        if map.insert(fragment.id, fragment).is_some() {
            return Err(format!("duplicated path fragment ID #{}", fragment.id));
        }
    }
    Ok(map)
}

/// A map mapping an artifact ID to an filepath.
/// See <https://github.com/bazelbuild/bazel/blob/51aae5ffa42dd6da63f61949d402a81f178fb99e/src/main/protobuf/analysis_v2.proto#L38>.
type Artifacts = std::collections::HashMap<u32, std::path::PathBuf>;

/// Builds the map of path fragments from a `aquery` query output.
pub(crate) fn get_artifacts(
    agc: &build_rust_proto::ActionGraphContainer,
) -> Result<Artifacts, String> {
    let paths = get_paths_fragments(agc)?;

    let mut artifacts = Artifacts::with_capacity(agc.artifacts.len());
    for art in agc.artifacts.iter() {
        let path = resolve_fragment_full_path(&paths, art.path_fragment_id)?;
        if artifacts.insert(art.id, path).is_some() {
            return Err(format!("duplicated fragment ID #{}", art.id));
        }
    }

    Ok(artifacts)
}

/// Resolves the full path to a path fragment.
fn resolve_fragment_full_path(
    fragments: &PathFragmentMap<'_>,
    leaf: u32,
) -> Result<std::path::PathBuf, String> {
    let leaf_fragment = fragments
        .get(&leaf)
        .ok_or_else(|| format!("leaf fragment #{leaf} does not exist"))?;
    let mut path = std::path::PathBuf::from(leaf_fragment.label.as_str());

    let mut frag = leaf_fragment;
    while frag.parent_id != 0 {
        let parent_frag = fragments.get(&frag.parent_id).ok_or_else(|| {
            format!(
                "fragment #{parent_id} parent of fragment #{frag_id} does not exist",
                parent_id = frag.parent_id,
                frag_id = frag.id
            )
        })?;
        path = std::path::Path::new(&parent_frag.label).join(&path);
        frag = parent_frag;
    }

    Ok(path)
}

/// Parses a serialized protobuf corresponding to an ActionGraph, and returns the artifacts.
pub(crate) fn get_artifacts_from_protobuf(
    stdout: impl std::convert::AsRef<[u8]>,
    exec_root: impl std::convert::AsRef<std::path::Path>,
) -> Result<Vec<std::path::PathBuf>, String> {
    let mut proto = build_rust_proto::ActionGraphContainer::new();
    <_ as protobuf::Message>::merge_from_bytes(&mut proto, stdout.as_ref())
        .map_err(|e| format!("failed to decode the protobuf message: {e}"))?;

    let exec_root = exec_root.as_ref();
    let artifacts = get_artifacts(&proto)?;

    let mut paths = Vec::new();
    for ids in proto.actions.iter().map(|a| a.output_ids.iter()) {
        for id in ids {
            if let Some(ar) = artifacts.get(id) {
                paths.push(exec_root.join(ar));
            } else {
                return Err(format!("artifact #{} does not exist", id));
            }
        }
    }

    Ok(paths)
}
