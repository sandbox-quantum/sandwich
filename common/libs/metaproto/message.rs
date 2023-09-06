//! Defines the [`Message`] struct.
//!
//! A [`Message`] is a representation of a protobuf message.
extern crate protobuf;

use super::oneof::OneOf;
use super::symbol_info::Info as SymbolInfo;

/// A field.
/// A field is either a pure field or a oneof:
///
/// ```ignore
/// message Example {
///     string field1 = 1; // Pure field
///     oneof choice {
///         string field2 = 2; // OneOf field
///     };
/// };
/// ```
pub enum Field<'d> {
    /// A pure field.
    Pure(SymbolInfo<'d>),
    OneOf(OneOf<'d>),
}

/// Implements [`std::fmt::Debug`] for [`Message`].
impl std::fmt::Debug for Field<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Pure(sym_info) => write!(f, "Field(Pure(info={sym_info:?}))"),
            Self::OneOf(oneof) => write!(f, "Field(OneOf({oneof:?}))"),
        }
    }
}

/// A Message.
pub struct Message<'d> {
    /// Message's fields.
    pub(crate) fields: Vec<Field<'d>>,
}

/// Implements [`std::fmt::Debug`] for [`Message`].
impl std::fmt::Debug for Message<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            r#"Message{{
    .fields = {fields:?},
}}"#,
            fields = self.fields,
        )
    }
}

/// Instantiates a [`Message`] from a protobuf message descriptor.
impl<'d> std::convert::TryFrom<&'d protobuf::descriptor::DescriptorProto> for Message<'d> {
    type Error = String;

    fn try_from(
        descriptor: &'d protobuf::descriptor::DescriptorProto,
    ) -> Result<Self, Self::Error> {
        #[derive(PartialEq, Eq, Debug)]
        enum FieldPosition {
            Pure(usize),
            OneOf(usize),
        }
        let mut fields = Vec::<FieldPosition>::new();

        let mut oneofs = Vec::<Option<OneOf>>::new();
        for oneof in descriptor.oneof_decl.iter() {
            oneofs.push(Some(OneOf::try_from(oneof)?));
        }

        let mut pure_fields = Vec::<Option<SymbolInfo>>::new();

        for field in descriptor.field.iter() {
            let name = field.name.as_deref().ok_or("field does not have a name")?;
            let sym_info = SymbolInfo::from(name);
            match field.oneof_index {
                Some(oneof_index) => match oneofs.get_mut(oneof_index as usize) {
                    Some(Some(oneof)) => {
                        oneof.fields.push(sym_info);
                        if oneof.fields.len() == 1 {
                            let pos = FieldPosition::OneOf(oneof_index as usize);
                            if fields.contains(&pos) {
                                return Err(format!("duplicated oneof: {}", oneof.info().name()));
                            }
                            fields.push(pos);
                        }
                    }
                    Some(None) => {
                        return Err(format!("Invalid oneof index {oneof_index}"));
                    }
                    None => {
                        return Err(format!("Unknown oneof at index {oneof_index}"));
                    }
                },
                None => {
                    let pos = FieldPosition::Pure(pure_fields.len());
                    log::debug!("Pushing pure field: {sym_info:?}");
                    pure_fields.push(Some(sym_info));
                    fields.push(pos);
                }
            };
        }

        let mut message = Self { fields: Vec::new() };

        log::debug!("fields position = {fields:?}");
        log::debug!("size of pure_fields: {}", pure_fields.len());

        for pos in fields {
            match pos {
                FieldPosition::Pure(i) => {
                    if i < pure_fields.len() {
                        message
                            .fields
                            .push(Field::Pure(pure_fields[i].take().ok_or_else(|| {
                                format!("invalid pure field at index {i}: already claimed")
                            })?));
                    } else {
                        return Err(format!(
                            "pure field index {i} out of range [0-{}]",
                            pure_fields.len()
                        ));
                    }
                }
                FieldPosition::OneOf(i) => {
                    if i < oneofs.len() {
                        message
                            .fields
                            .push(Field::OneOf(oneofs[i].take().ok_or_else(|| {
                                format!("invalid oneof field at index {i}: already claimed")
                            })?));
                    } else {
                        return Err(format!(
                            "oneof field index {i} out of range [0-{}]",
                            oneofs.len()
                        ));
                    }
                }
            }
        }
        Ok(message)
    }
}

/// Implements [`Message`].
impl<'d> Message<'d> {
    /// Returns the fields.
    pub fn fields(&self) -> &Vec<Field<'d>> {
        &self.fields
    }
}

/// Type for a message descriptor.
pub const DESCRIPTOR_TYPE: i32 = 4;

/// Type for a message field descriptor.
pub const FIELD_DESCRIPTOR_TYPE: i32 = 2;

#[cfg(test)]
mod test {
    /// Tests the constructor of [`super::Message`] with an empty descriptor.
    #[test]
    fn test_message_constructor_empty_descriptor() {
        let mdesc = protobuf::descriptor::DescriptorProto::new();

        super::Message::try_from(&mdesc).expect("constructor failed");
    }

    /// Tests the constructor of [`super::Message`] with a field that has no name.
    #[test]
    fn test_message_constructor_with_field_missing_name() {
        let mut mdesc = protobuf::descriptor::DescriptorProto::new();

        mdesc
            .field
            .push(protobuf::descriptor::FieldDescriptorProto::new());
        let field = mdesc.field.last_mut().expect("no last value");
        field.name = None;

        super::Message::try_from(&mdesc)
            .expect_err("constructor succeed, but it should have failed");

        let field = mdesc.field.last_mut().expect("no last value");
        field.name = Some("f13ld".into());
        super::Message::try_from(&mdesc).expect("constructor failed");
    }

    /// Tests the constructor of [`super::Message`] with a field that belongs
    /// to an unexisting oneof.
    #[test]
    fn test_message_constructor_with_errors() {
        let mut mdesc = protobuf::descriptor::DescriptorProto::new();

        mdesc
            .field
            .push(protobuf::descriptor::FieldDescriptorProto::new());
        let field = mdesc.field.last_mut().expect("no last value");

        field.name = Some("f13ld".into());
        field.oneof_index = Some(42);
        let err = super::Message::try_from(&mdesc)
            .expect_err("constructor succeeded, but it should have failed");
        assert_eq!(err, "Unknown oneof at index 42");
    }

    /// Tests the constructor of [`super::Message`] with a oneof has no name.
    #[test]
    fn test_message_constructor_oneof_missing_name() {
        let mut mdesc = protobuf::descriptor::DescriptorProto::new();

        mdesc
            .oneof_decl
            .push(protobuf::descriptor::OneofDescriptorProto::new());
        let oneof = mdesc.oneof_decl.last_mut().expect("no last value");
        oneof.name = None;

        super::Message::try_from(&mdesc)
            .expect_err("constructor succeed, but it should have failed");
    }
}
