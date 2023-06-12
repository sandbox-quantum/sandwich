///! Defines [`Info`].
///!
///! [`Info`] is a struct that reads and parses [`protobuf::descriptor::SourceCodeInfo`].
extern crate log;
extern crate protobuf;

/// Symbol's comments.
///
/// There are three kinds of comments. For instance, taking the following message:
///
/// ```ignore
/// // AAA.
/// message TestMsg { // BBB
///     // XX
///     string field1 = 1;
///
///     // CCC
/// };
/// ```
///
///  - `AAA` are the leading comments.
///  - `BBB` are the trailing comments.
///  - `CCC` are the detached comments.
#[derive(Clone)]
pub struct Comments<'s> {
    /// Leading comments.
    pub(crate) leading: Option<&'s str>,

    /// Trailing comments.
    pub(crate) trailing: Option<&'s str>,

    /// Detached comments.
    pub(crate) detached: Vec<&'s str>,
}

/// Implements [`std::fmt::Debug`] for [`Comments`].
impl std::fmt::Debug for Comments<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            r#"Comments{{
    .leading = {leading:?},
    .trailing = {trailing:?},
    .detached = {detached:?},
}}"#,
            leading = self.leading,
            trailing = self.trailing,
            detached = self.detached,
        )
    }
}

use protobuf::descriptor::source_code_info::Location as PBLocation;

/// Instantiates a [`Comments`] from a [`protobuf::descriptor::source_code_info::Location`].
impl<'s> std::convert::From<&'s PBLocation> for Comments<'s> {
    fn from(loc: &'s PBLocation) -> Self {
        Self {
            leading: loc.leading_comments.as_deref(),
            trailing: loc.trailing_comments.as_deref(),
            detached: loc
                .leading_detached_comments
                .iter()
                .map(|l| l.as_ref())
                .collect(),
        }
    }
}

/// Implements [`Comments`].
impl<'s> Comments<'s> {
    /// Returns the laading comments.
    pub fn leading(&self) -> Option<&'s str> {
        self.leading
    }

    /// Returns the laading comments.
    pub fn trailing(&self) -> Option<&'s str> {
        self.trailing
    }

    /// Returns the laading comments.
    pub fn detached(&self) -> &[&'s str] {
        &self.detached[..]
    }
}

/// Source code location.
///
/// This structure locates the source code of a symbol within its source file.
/// This uses the span given by the protobuf API.
/// Spans are defined in [`protobuf::descriptor::source_code_info::Location`]:
/// <https://docs.rs/protobuf/latest/protobuf/descriptor/source_code_info/struct.Location.html#structfield.span>
///
/// > Always has exactly three or four elements: start line, start column,
/// > end line (optional, otherwise assumed same as start line), end column.
/// > These are packed into a single field for efficiency. Note that line and
/// > column numbers are zero-indexed – typically you will want to add 1 to each
/// > before displaying to a user.
///
/// Indexes starts at 0.
#[derive(PartialEq, Eq)]
pub struct Location {
    /// Start line.
    pub(crate) start_line: usize,

    /// End line.
    pub(crate) end_line: usize,

    /// Start column.
    /// This is the position of the first char within the first line, defined
    /// by `start_line`.
    pub(crate) start_column: usize,

    /// End column.
    /// This is the position of the last char within the last line, defined
    /// by `end_line`.
    pub(crate) end_column: usize,
}

/// Implements [`std::fmt::Debug`] for [`Location`]
impl std::fmt::Debug for Location {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Location({start_line}:{start_column} -> {end_line}:{end_column})",
            start_line = self.start_line,
            start_column = self.start_column,
            end_line = self.end_line,
            end_column = self.end_column,
        )
    }
}

/// Instantiates a [`Location`] from a span.
impl std::convert::TryFrom<&[i32]> for Location {
    type Error = String;

    fn try_from(span: &[i32]) -> Result<Self, Self::Error> {
        if span.len() < 3 {
            return Err(format!(
                "invalid span: expected at least 3 elements, got {n} element(s)",
                n = span.len()
            ));
        }

        if span.len() > 4 {
            return Err(format!(
                "invalid span: expected at most 4 elements, got {n} element(s)",
                n = span.len()
            ));
        }
        let start_line = span[0];
        let start_column = span[1];

        let (end_line, end_column) = if let Some(n) = span.get(3) {
            (span[2], *n)
        } else {
            (start_line, span[2])
        };

        if start_line < 0 {
            return Err(format!(
                "invalid span `start_line` value: expected a value >= 0, got {start_line}"
            ));
        }
        let start_line = start_line as usize;

        if end_line < 0 {
            return Err(format!(
                "invalid span `end_line` value: expected a value >= 0, got {start_line}"
            ));
        }
        let end_line = end_line as usize;

        if end_line < start_line {
            return Err(format!("invalid span `start_line`/`end_line` value: expected `start_line` <= `end_line`, got `start_line`={start_line}, `end_line`={end_line}"));
        }

        if start_column < 0 {
            return Err(format!(
                "invalid span `start_column` value: expected a value >= 0, got {start_column}"
            ));
        }
        let start_column = start_column as usize;

        if end_column < 0 {
            return Err(format!(
                "invalid span `end_column` value: expected a value >= 0, got {start_column}"
            ));
        }
        let end_column = end_column as usize;

        if (start_line == end_line) && (start_column > end_column) {
            return Err(format!("invalid span `start_column`/`end_column` value: expected `start_column` <= `end_column`, got `start_column`={start_column}, `end_column`={end_column}, when start_line == end_line"));
        }

        Ok(Self {
            start_line,
            start_column,
            end_line,
            end_column,
        })
    }
}

/// Source code information for a symbol.
pub struct Symbol<'s> {
    /// Comments.
    pub(crate) comments: Comments<'s>,

    /// The location in the source file.
    pub(crate) location: Location,
}

/// Implements [`std::fmt::Debug`] for [`Symbol`].
impl std::fmt::Debug for Symbol<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            r#"Symbol{{
    .comments = {comments:?},
    .location = {location:?},
}}"#,
            comments = self.comments,
            location = self.location,
        )
    }
}

/// Instantiates a [`Symbol`] from a [`protobuf::descriptor::source_code_info::Location`].
impl<'s> std::convert::TryFrom<&'s PBLocation> for Symbol<'s> {
    type Error = String;

    fn try_from(pbloc: &'s PBLocation) -> Result<Self, Self::Error> {
        Ok(Self {
            comments: Comments::from(pbloc),
            location: Location::try_from(&pbloc.span[..])?,
        })
    }
}

/// Implements [`Symbol`].
impl<'s> Symbol<'s> {
    /// Returns the comments.
    pub fn comments(&self) -> &Comments<'s> {
        &self.comments
    }

    /// Returns its location.
    pub fn location(&self) -> &Location {
        &self.location
    }
}

/// Source code information for a message.
pub struct Message<'s> {
    /// Message's information.
    pub(crate) info: Symbol<'s>,

    /// Information of the message's fields.
    pub(crate) fields: Vec<Symbol<'s>>,

    /// Information of the message's oneofs.
    pub(crate) oneofs: Vec<Symbol<'s>>,
}

/// Implements [`std::fmt::Debug`] for [`Message`].
impl std::fmt::Debug for Message<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            r#"Message{{
    .info = {info:?},
    .fields = {fields:?},
    .oneofs = {oneofs:?},
}}"#,
            info = self.info,
            fields = self.fields,
            oneofs = self.oneofs,
        )
    }
}

/// Implements [`Message`].
impl<'s> Message<'s> {
    /// Returns the information of the message's symbol.
    pub fn info(&self) -> &Symbol<'s> {
        &self.info
    }

    /// Returns the fields of the message.
    pub fn fields(&self) -> &[Symbol<'s>] {
        &self.fields[..]
    }

    /// Returns the oneofs of the message.
    pub fn oneofs(&self) -> &[Symbol<'s>] {
        &self.oneofs[..]
    }
}

/// Source code information for an enum.
pub struct Enum<'s> {
    /// Enum's information.
    pub(crate) info: Symbol<'s>,

    /// Information of the enum's values.
    pub(crate) values: Vec<Symbol<'s>>,
}

/// Implements [`std::fmt::Debug`] for [`Enum`].
impl std::fmt::Debug for Enum<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            r#"Enum{{
    .info = {info:?},
    .values = {values:?},
}}"#,
            info = self.info,
            values = self.values,
        )
    }
}

/// Implements [`Enum`].
impl<'s> Enum<'s> {
    /// Returns the information of the enum's symbol.
    pub fn info(&self) -> &Symbol<'s> {
        &self.info
    }

    /// Returns the values of the enum.
    pub fn values(&self) -> &[Symbol<'s>] {
        &self.values[..]
    }
}

/// Source code information for a file.
pub struct Info<'s> {
    /// Messages.
    /// Indexes follow the order of the definitions of the messages, according
    /// to google/protobuf/descriptor.proto.
    pub(crate) messages: Vec<Message<'s>>,

    /// Enums.
    /// Indexes follow the order of the definitions of the enums, according
    /// to google/protobuf/descriptor.proto.
    pub(crate) enums: Vec<Enum<'s>>,
}

/// Implements [`std::fmt::Debug`] for [`Info`].
impl std::fmt::Debug for Info<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            r#"Info{{
    .messages = {messages:?},
    .enums = {enums:?},
}}"#,
            messages = self.messages,
            enums = self.enums,
        )
    }
}

use protobuf::descriptor::SourceCodeInfo as PBSourceCodeInfo;

/// Instantiates a [`Info`] from a [`protobuf::descriptor::SourceCodeInfo`].
impl<'s> std::convert::TryFrom<&'s PBSourceCodeInfo> for Info<'s> {
    type Error = String;

    fn try_from(pbloc: &'s PBSourceCodeInfo) -> Result<Self, Self::Error> {
        let mut messages = Vec::<Message>::new();
        let mut enums = Vec::<Enum>::new();
        for loc in pbloc.location.iter().filter(|l| l.path.len() >= 2) {
            let path = &loc.path;
            match path[..] {
                // Message

                // Message.pure_fields
                [super::message::DESCRIPTOR_TYPE, msg_index] => {
                    let msg_index = msg_index as usize;
                    if msg_index != messages.len() {
                        return Err(format!(
                            "message indexes mismatch: expected {msg_index}, got {}",
                            messages.len()
                        ));
                    }
                    messages.push(Message {
                        info: Symbol::try_from(loc)?,
                        fields: Vec::new(),
                        oneofs: Vec::new(),
                    });
                }
                [super::message::DESCRIPTOR_TYPE, msg_index, super::message::FIELD_DESCRIPTOR_TYPE, field_index] =>
                {
                    let msg_index = msg_index as usize;
                    let field_index = field_index as usize;

                    let msg = messages
                        .get_mut(msg_index)
                        .ok_or_else(|| format!("missing message: wanted {msg_index}"))?;
                    if field_index != msg.fields.len() {
                        return Err(format!("field indexes mismatch: expected {field_index} for message {msg_index}, got {}", msg.fields.len()));
                    }
                    msg.fields.push(Symbol::try_from(loc)?);
                }

                // Message.oneof
                [super::message::DESCRIPTOR_TYPE, msg_index, super::oneof::DESCRIPTOR_TYPE, oneof_index] =>
                {
                    let msg_index = msg_index as usize;
                    let oneof_index = oneof_index as usize;

                    let msg = messages
                        .get_mut(msg_index)
                        .ok_or_else(|| format!("missing message: wanted {msg_index}"))?;
                    if oneof_index != msg.oneofs.len() {
                        return Err(format!("oneof indexes mismatch: expected {oneof_index} for message {msg_index}, got {}", msg.oneofs.len()));
                    }
                    msg.oneofs.push(Symbol::try_from(loc)?);
                }

                // Unknown descriptor
                [super::message::DESCRIPTOR_TYPE, msg_index, desc_type, unknown_index] => {
                    log::warn!(
                    "unknown descriptor type {desc_type} with index {unknown_index} for message {msg_index}"
                )
                }

                // Enum descriptors
                [super::enum_::DESCRIPTOR_TYPE, enum_index] => {
                    let enum_index = enum_index as usize;
                    if enum_index != enums.len() {
                        return Err(format!(
                            "enum indexes mismatch: expected {enum_index}, got {}",
                            enums.len()
                        ));
                    }
                    enums.push(Enum {
                        info: Symbol::try_from(loc)?,
                        values: Vec::new(),
                    });
                }
                [super::enum_::DESCRIPTOR_TYPE, enum_index, super::enum_::VALUE_DESCRIPTOR_TYPE, value_index] =>
                {
                    let enum_index = enum_index as usize;
                    let value_index = value_index as usize;

                    let e = enums
                        .get_mut(enum_index)
                        .ok_or_else(|| format!("missing enum: wanted {enum_index}"))?;
                    if value_index != e.values.len() {
                        return Err(format!("value indexes mismatch: expected {value_index} for enum {enum_index}, got {}", e.values.len()));
                    }
                    e.values.push(Symbol::try_from(loc)?);
                }
                [super::enum_::DESCRIPTOR_TYPE, enum_index, desc_type, unknown_index] => {
                    log::warn!(
                        "unknown descriptor type {desc_type} with index {unknown_index} for enum {enum_index}"
                    )
                }

                [desc_type, unknown_index] => log::warn!(
                    "unknown primary descriptor type {desc_type} with index {unknown_index}"
                ),
                _ => log::warn!("unknown path {path:?}"),
            }
        }
        Ok(Self { messages, enums })
    }
}

/// Implements [`Info`].
impl<'s> Info<'s> {
    /// Returns all the messages.
    pub fn messages(&self) -> &[Message<'s>] {
        &self.messages[..]
    }

    /// Returns the i^th message.
    pub fn message(&self, i: usize) -> Option<&Message<'s>> {
        self.messages.get(i)
    }

    /// Returns all the enums.
    pub fn enums(&self) -> &[Enum<'s>] {
        &self.enums[..]
    }

    /// Returns the i^th enum.
    pub fn enum_(&self, i: usize) -> Option<&Enum<'s>> {
        self.enums.get(i)
    }
}

#[cfg(test)]
mod test {
    /// Tests the constructor of [`super::Comments`] from a [`super::PBLocation`].
    #[test]
    fn test_comments_constructor() {
        let mut location = super::PBLocation::new();
        location.set_leading_comments("leading".into());
        let loc = super::Comments::from(&location);
        assert_eq!(loc.leading().as_deref(), Some("leading"));
        assert_eq!(loc.trailing(), None);
        assert!(loc.detached().is_empty());

        location.set_trailing_comments("trailing".into());
        let loc = super::Comments::from(&location);
        assert_eq!(loc.leading().as_deref(), Some("leading"));
        assert_eq!(loc.trailing().as_deref(), Some("trailing"));
        assert!(loc.detached().is_empty());

        location.leading_detached_comments.push("a".into());
        location.leading_detached_comments.push("b".into());
        let loc = super::Comments::from(&location);
        assert_eq!(loc.leading().as_deref(), Some("leading"));
        assert_eq!(loc.trailing().as_deref(), Some("trailing"));
        assert_eq!(loc.detached(), vec!["a", "b"]);
    }

    /// Tests the constructor of [`super::Location`] from a span.
    #[test]
    fn test_location_constructor() {
        use super::Location;

        let mut span = Vec::<i32>::new();

        for i in 0..3 {
            let loc = Location::try_from(span.as_ref());
            assert_eq!(
                loc,
                Err(format!(
                    "invalid span: expected at least 3 elements, got {i} element(s)"
                ))
            );
            span.push(i);
        }

        let loc = Location::try_from(span.as_ref());
        assert_eq!(
            loc,
            Ok(Location {
                start_line: 0,
                start_column: 1,
                end_column: 2,
                end_line: 0
            })
        );

        span.push(10);
        let loc = Location::try_from(span.as_ref());
        assert_eq!(
            loc,
            Ok(Location {
                start_line: 0,
                start_column: 1,
                end_column: 10,
                end_line: 2
            })
        );
    }

    /// Tests invalid spans.
    #[test]
    fn test_location_invalid_spans() {
        use super::Location;

        let span = vec![0i32; 5];

        let loc = Location::try_from(span.as_ref());
        assert_eq!(
            loc,
            Err("invalid span: expected at most 4 elements, got 5 element(s)".into())
        );

        // Test with end_line < start_line.
        let span = vec![1i32, 0i32, 0i32, 4i32];
        let loc = Location::try_from(span.as_ref());
        assert_eq!(loc, Err("invalid span `start_line`/`end_line` value: expected `start_line` <= `end_line`, got `start_line`=1, `end_line`=0".into()));

        // Test with start_line == end_line, but end_column < start_column
        let span = vec![1i32, 42i32, 1i32, 1i32];
        let loc = Location::try_from(span.as_ref());
        assert_eq!(loc, Err("invalid span `start_column`/`end_column` value: expected `start_column` <= `end_column`, got `start_column`=42, `end_column`=1, when start_line == end_line".into()));
    }

    /// Tests constructor of [`super::Symbol`].
    #[test]
    fn test_symbol_constructor() {
        use super::Symbol;

        let mut location = super::PBLocation::new();
        location.set_leading_comments("leading".into());
        location.set_trailing_comments("trailing".into());
        location
            .leading_detached_comments
            .extend(vec!["two".into(), "lines".into()]);

        location.span = vec![1i32, 0i32, 12i32, 3i32];

        let sym = Symbol::try_from(&location).expect("constructor failed");
        assert_eq!(sym.comments().leading(), Some("leading"));
        assert_eq!(sym.comments().trailing(), Some("trailing"));
        assert_eq!(sym.comments().detached(), ["two", "lines"]);

        let loc = sym.location();
        assert_eq!(loc.start_line, 1usize);
        assert_eq!(loc.start_column, 0usize);
        assert_eq!(loc.end_line, 12usize);
        assert_eq!(loc.end_column, 3usize);

        location.span = vec![1i32, 0i32, 0i32, 3i32];
        Symbol::try_from(&location).expect_err("constructor succeed, but it should have failed");
    }
}
