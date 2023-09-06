//! Defines the [`Enum`] struct.
//!
//! A [`Enum`] is a representation of a protobuf enumeration.
extern crate protobuf;

use super::symbol_info::Info as SymbolInfo;

/// A Enum.
pub struct Enum<'d> {
    /// Values belonging to the enum.
    pub(crate) values: Vec<SymbolInfo<'d>>,
}

/// Implements [`std::fmt::Debug`] for [`Enum`].
impl std::fmt::Debug for Enum<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            r#"Enum{{
    .values = {values:?},
        }}"#,
            values = self.values
        )
    }
}

/// Instantiates a [`Enum`] from a protobuf enum descriptor.
impl<'d> std::convert::TryFrom<&'d protobuf::descriptor::EnumDescriptorProto> for Enum<'d> {
    type Error = String;

    fn try_from(
        descriptor: &'d protobuf::descriptor::EnumDescriptorProto,
    ) -> Result<Self, Self::Error> {
        let mut values = Vec::new();
        for value in descriptor.value.iter() {
            let name = value
                .name
                .as_deref()
                .ok_or("enum value does not have a name")?;
            values.push(SymbolInfo::from(name));
        }

        Ok(Self { values })
    }
}

/// Implements [`Enum`].
impl<'d> Enum<'d> {
    /// Returns the values.
    pub fn values(&self) -> &Vec<SymbolInfo<'d>> {
        &self.values
    }
}

/// Type for a enum descriptor.
pub const DESCRIPTOR_TYPE: i32 = 5;
/// Type for a enum value descriptor.
pub const VALUE_DESCRIPTOR_TYPE: i32 = 2;

#[cfg(test)]
mod test {
    /// Tests the constructor of [`super::Enum`].
    #[test]
    fn test_enum_constructor() {
        let e = protobuf::descriptor::EnumDescriptorProto::new();
        super::Enum::try_from(&e).expect("constructor failed");
    }

    /// Tests the constructor of [`super::Enum`] with an invalid enum value.
    #[test]
    fn test_enum_constructor_invalid_enum_value() {
        let mut e = protobuf::descriptor::EnumDescriptorProto::new();
        e.value
            .push(protobuf::descriptor::EnumValueDescriptorProto::new());

        super::Enum::try_from(&e).expect_err("constructor succeed, but it should have failed");

        let v = e.value.last_mut().expect("no last element");
        v.name = Some("name".into());

        let e = super::Enum::try_from(&e).expect("constructor failed");

        assert_eq!(e.values.len(), 1);
    }
}
