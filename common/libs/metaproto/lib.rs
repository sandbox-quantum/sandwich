//! Defines [`MetaProto`] handle.
extern crate log;
extern crate protobuf;

pub mod enum_;
pub mod file_info;
pub mod message;
pub mod oneof;
pub mod source_info;
pub mod symbol;
pub mod symbol_info;

use file_info::Info as FileInfo;
use symbol::Symbol;

/// MetaProto handle.
pub struct MetaProto<'r> {
    /// All symbols.
    symbols: Vec<Symbol<'r>>,
}

/// Implements [`std::fmt::Debug`] for [`MetaProto`].
impl std::fmt::Debug for MetaProto<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            r#"MetaProto{{
    .symbols = {symbols:?}
}}"#,
            symbols = self.symbols
        )
    }
}

/// Implements [`std::fmt::Display`] for [`MetaProto`].
impl std::fmt::Display for MetaProto<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Resolves the source code of a symbol  based on the symbol's source info and
/// The file's information.
pub(crate) fn resolve_symbol_source(
    file_info: &file_info::Info,
    sym_source_info: &source_info::Symbol<'_>,
) -> Option<Vec<String>> {
    let loc = sym_source_info.location();

    log::debug!("Resolving loc {loc:?}");

    let nlines = file_info.content.len();
    if loc.start_line > nlines {
        log::warn!(
            "source info start_line ({start_line}) out of range ({nlines})",
            start_line = loc.start_line
        );
        return None;
    }

    if loc.end_line >= nlines {
        log::warn!(
            "source info end_line ({end_line}) out of range ({nlines})",
            end_line = loc.end_line
        );
        return None;
    }

    let mut content = Vec::<String>::new();

    let sl = &file_info.content[loc.start_line];
    if loc.start_line == loc.end_line {
        if loc.start_column > sl.len() {
            log::warn!(
                "start_column ({start_column}) out of range ({len}). Line is {sl}",
                start_column = loc.start_column,
                len = sl.len()
            );
            return None;
        }
        content.push(sl[loc.start_column..loc.end_column].into());
    } else {
        let mut i = loc.start_line;
        let mut c = loc.start_column;
        while i <= loc.end_line {
            let sl = &file_info.content[i];
            if c > sl.len() {
                log::warn!("start_column ({c}) out of range ({len})", len = sl.len());
                return None;
            }
            if i == loc.end_line {
                if loc.end_column > sl.len() {
                    log::warn!(
                        "end_column ({end_column}) out of range ({len})",
                        end_column = loc.end_column,
                        len = sl.len()
                    );
                    return None;
                }
                content.push(sl[c..loc.end_column].into());
            } else {
                content.push(sl.into());
                c = 0;
            }
            i += 1;
        }
    }
    Some(content)
}

/// Instantiates a [`MetaProto`] from a [`protobuf::plugin::CodeGeneratorRequest`].
impl<'r> std::convert::TryFrom<&'r protobuf::plugin::CodeGeneratorRequest> for MetaProto<'r> {
    type Error = String;
    fn try_from(req: &'r protobuf::plugin::CodeGeneratorRequest) -> Result<Self, Self::Error> {
        log::debug!(
            "reading the request: {} file(s) to read.",
            req.proto_file.len()
        );
        let mut handle = Self::default();
        for file in req.proto_file.iter() {
            handle.push(file)?;
        }
        Ok(handle)
    }
}

/// Implements [`std::default::Default`] for [`MetaProto`].
impl std::default::Default for MetaProto<'_> {
    fn default() -> Self {
        Self::new()
    }
}

/// Implements [`MetaProto`].
impl<'d> MetaProto<'d> {
    /// Instantiates a new [`MetaProto`].
    pub fn new() -> Self {
        Self {
            symbols: Vec::new(),
        }
    }

    /// Appends a protobuf file using its [`protobuf::descriptor::FileDescriptorProto`].
    pub fn push(
        &mut self,
        fdesc: &'d protobuf::descriptor::FileDescriptorProto,
    ) -> Result<(), String> {
        let file_info = FileInfo::try_from(fdesc)?;
        log::debug!("reading {file_info:?}");

        let mut symbols = Vec::new();
        for msg in fdesc.message_type.iter() {
            symbols.push(symbol::Symbol::try_from((file_info.clone(), msg))?);
        }

        for e in fdesc.enum_type.iter() {
            symbols.push(symbol::Symbol::try_from((file_info.clone(), e))?);
        }

        let mut msg_index = 0;
        let mut enum_index = 0;
        for sym in symbols.iter_mut() {
            let name = sym.info().name();
            match sym.content {
                symbol::Content::Message(ref mut msg) => {
                    let msg_source = if let Some(si) = file_info.source_info.message(msg_index) {
                        si
                    } else {
                        log::warn!("cannot find source info for message {name}");
                        msg_index += 1;
                        continue;
                    };
                    msg_index += 1;
                    sym.info.comments = Some(msg_source.info.comments().clone());

                    if let Some(src) = resolve_symbol_source(&file_info, &msg_source.info) {
                        sym.info.source = src;
                    }

                    let mut field_index = 0;
                    let mut oneof_index = 0;
                    'outer: for field in msg.fields.iter_mut() {
                        match field {
                            message::Field::Pure(ref mut pure_field) => {
                                if let Some(field_source) = msg_source.fields().get(field_index) {
                                    pure_field.comments = Some(field_source.comments().clone());
                                    if let Some(src) =
                                        resolve_symbol_source(&file_info, field_source)
                                    {
                                        pure_field.source = src;
                                    }
                                    field_index += 1;
                                } else {
                                    log::warn!("no source info for pure field #{field_index} in message {name}");
                                    break 'outer;
                                }
                            }
                            message::Field::OneOf(ref mut oneof_field) => {
                                if let Some(oneof_source) = msg_source.oneofs().get(oneof_index) {
                                    oneof_field.info.comments =
                                        Some(oneof_source.comments().clone());
                                    if let Some(src) =
                                        resolve_symbol_source(&file_info, oneof_source)
                                    {
                                        oneof_field.info.source = src;
                                    }
                                    oneof_index += 1
                                } else {
                                    log::warn!(
                                        "no source info for oneof #{oneof_index} in message {name}"
                                    );
                                    break 'outer;
                                }
                                for pure_field in oneof_field.fields.iter_mut() {
                                    if let Some(field_source) = msg_source.fields().get(field_index)
                                    {
                                        pure_field.comments = Some(field_source.comments().clone());
                                        if let Some(src) =
                                            resolve_symbol_source(&file_info, field_source)
                                        {
                                            pure_field.source = src;
                                        }
                                        field_index += 1;
                                    } else {
                                        log::warn!("no source info for pure field #{field_index} in oneof in message {name}");
                                        break 'outer;
                                    }
                                }
                            }
                        }
                    }
                }
                symbol::Content::Enum(ref mut e) => {
                    let enum_source = if let Some(si) = file_info.source_info.enum_(enum_index) {
                        si
                    } else {
                        log::warn!("cannot find source info for enum {name}");
                        enum_index += 1;
                        continue;
                    };
                    enum_index += 1;
                    sym.info.comments = Some(enum_source.info.comments().clone());

                    if let Some(src) = resolve_symbol_source(&file_info, &enum_source.info) {
                        sym.info.source = src;
                    }

                    for (value_index, value) in e.values.iter_mut().enumerate() {
                        if let Some(value_source) = enum_source.values().get(value_index) {
                            value.comments = Some(value_source.comments().clone());
                            if let Some(src) = resolve_symbol_source(&file_info, value_source) {
                                value.source = src;
                            }
                        } else {
                            log::warn!(
                                "cannot find source info for value #{value_index} in enum {name}"
                            );
                        }
                    }
                }
            }
        }
        self.symbols.extend(symbols);
        Ok(())
    }

    /// Returns the symbols.
    pub fn symbols(&self) -> &[Symbol<'d>] {
        &self.symbols[..]
    }
}

#[cfg(test)]
pub(crate) mod test {
    /// Path to a protobuf file.
    pub(crate) const TEST_PROTO_PATH: &str = "common/libs/metaproto/test.proto";
}
