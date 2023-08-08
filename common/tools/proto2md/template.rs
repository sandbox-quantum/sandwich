//! Template routines.
extern crate metaproto;

use metaproto::enum_::Enum;
use metaproto::message::Message;
use metaproto::oneof::OneOf;
use metaproto::symbol::Symbol;
use metaproto::symbol_info::Info as SymbolInfo;

use super::FileContent;

/// Default string for empty source code.
const DEFAULT_STRING_EMPTY_SOURCE_CODE: &str = "_no content provided_";

/// Default string for empty description.
const DEFAULT_STRING_EMPTY_DESCRIPTION: &str = "_no description provided_";

/// Resolves and formats the source code of a symbol.
fn format_symbol_source_code(symbol_info: &SymbolInfo<'_>) -> String {
    let mut source = String::new();
    for line in symbol_info.source() {
        source.push_str(line);
        source.push('\n');
    }
    if source.is_empty() {
        source = DEFAULT_STRING_EMPTY_SOURCE_CODE.into();
    }

    source.trim().into()
}

/// Resolves an formats the description of a symbol.
fn format_symbol_description<'d>(symbol_info: &SymbolInfo<'d>) -> &'d str {
    symbol_info
        .comments()
        .and_then(|comments| comments.leading())
        .unwrap_or(DEFAULT_STRING_EMPTY_DESCRIPTION)
        .trim()
}

/// Produces the content for a field.
fn produce_message_field_content(os: &mut String, field: &SymbolInfo<'_>) {
    os.push_str(&format!(
        r#"
### `{field_name}`

{field_description}

```proto
{field_source}
```

"#,
        field_name = field.name(),
        field_description = format_symbol_description(field),
        field_source = format_symbol_source_code(field),
    ));
}

/// Produces the content for a oneof.
fn produce_message_oneof_content(os: &mut String, oneof: &OneOf<'_>) {
    let oneof_info = oneof.info();

    os.push_str(&format!(
        r#"
### oneof `{oneof_name}`

{oneof_description}

```proto
{oneof_source}
```

"#,
        oneof_name = oneof_info.name(),
        oneof_description = format_symbol_description(oneof_info),
        oneof_source = format_symbol_source_code(oneof_info),
    ));

    for field in oneof.fields() {
        os.push_str(&format!(
            r#"
#### `{field_name}`

{field_description}

```proto
{field_source}
```

"#,
            field_name = field.name(),
            field_description = format_symbol_description(field),
            field_source = format_symbol_source_code(field),
        ));
    }
}

/// Produces the content for a message.
pub fn produce_message_content(symbol: &Symbol<'_>, msg: &Message<'_>) -> FileContent {
    let sym_info = symbol.info();
    let mut os = String::new();
    let filename = format!(
        "{package}.{msg_name}",
        package = symbol.file_info().package_name,
        msg_name = sym_info.name(),
    );

    os.push_str(&format!(
        r#"
`{filename}`

## Description

{msg_description}

```proto
{msg_source}
```

"#,
        msg_description = format_symbol_description(sym_info),
        msg_source = format_symbol_source_code(sym_info),
    ));

    os.push_str("## Fields\n\n");

    for field in msg.fields() {
        match field {
            metaproto::message::Field::Pure(pure_field) => {
                produce_message_field_content(&mut os, pure_field)
            }
            metaproto::message::Field::OneOf(oneof_field) => {
                produce_message_oneof_content(&mut os, oneof_field)
            }
        }
    }

    FileContent {
        content: os,
        name: filename,
    }
}

/// Produces the content for a enum value.
fn produce_enum_value_content(os: &mut String, value: &SymbolInfo<'_>) {
    os.push_str(&format!(
        r#"
### `{value_name}`

{value_description}

```proto
{value_source}
```

"#,
        value_name = value.name(),
        value_description = format_symbol_description(value),
        value_source = format_symbol_source_code(value),
    ));
}

/// Produces the content for an enum.
pub fn produce_enum_content(symbol: &Symbol<'_>, e: &Enum<'_>) -> FileContent {
    let sym_info = symbol.info();
    let mut os = String::new();
    let filename = format!(
        "{package}.{enum_name}",
        package = symbol.file_info().package_name,
        enum_name = sym_info.name(),
    );

    os.push_str(&format!(
        r#"
`{filename}`

## Description

{enum_description}

```proto
{enum_source}
```

"#,
        enum_description = format_symbol_description(sym_info),
        enum_source = format_symbol_source_code(sym_info),
    ));

    os.push_str("## Values\n\n");

    for value in e.values() {
        produce_enum_value_content(&mut os, value);
    }

    FileContent {
        content: os,
        name: filename,
    }
}
