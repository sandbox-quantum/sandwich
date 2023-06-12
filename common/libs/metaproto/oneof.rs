///! Defines [`OneOf`].
extern crate protobuf;

use super::symbol_info::Info as SymbolInfo;

/// A Oneof.
pub struct OneOf<'d> {
    /// Symbol information for the oneof.
    pub(crate) info: SymbolInfo<'d>,

    /// Fields belonging to the oneof.
    pub(crate) fields: Vec<SymbolInfo<'d>>,
}

/// Implements [`std::fmt::Debug`] for [`Oneof`].
impl std::fmt::Debug for OneOf<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            r#"Oneof{{
    .info = {info:?},
    .fields = {fields:?},
}}"#,
            info = self.info,
            fields = self.fields,
        )
    }
}

/// Instantiates a [`Message`] from a protobuf oneof descriptor.
impl<'d> std::convert::TryFrom<&'d protobuf::descriptor::OneofDescriptorProto> for OneOf<'d> {
    type Error = String;

    fn try_from(
        descriptor: &'d protobuf::descriptor::OneofDescriptorProto,
    ) -> Result<Self, Self::Error> {
        let name = descriptor
            .name
            .as_deref()
            .ok_or("oneof does not have a name")?;
        Ok(Self {
            info: SymbolInfo::from(name),
            fields: Vec::new(),
        })
    }
}

/// Implements [`OneOf`].
impl<'d> OneOf<'d> {
    /// Returns the symbol information.
    pub fn info(&self) -> &SymbolInfo<'d> {
        &self.info
    }

    /// Returns the fields belonging to the Oneof.
    pub fn fields(&self) -> &[SymbolInfo<'d>] {
        &self.fields[..]
    }
}

/// Type for a oneof descriptor.
pub const DESCRIPTOR_TYPE: i32 = 8;

#[cfg(test)]
mod test {
    /// Tests the constructor of [`super::OneOf`].
    #[test]
    fn test_oneof_constructor() {
        let mut odesc = protobuf::descriptor::OneofDescriptorProto::new();
        super::OneOf::try_from(&odesc).expect_err("constructor succeed, but it should have failed");

        odesc.name = Some("0n30f".into());
        let o = super::OneOf::try_from(&odesc).expect("constructor failed");

        assert_eq!(o.fields().len(), 0);
        assert_eq!(o.info().name(), "0n30f");
    }
}
