///! Defines the [`Symbol`] struct.
extern crate protobuf;

use super::file_info::Info as FileInfo;
use super::symbol_info::Info as SymbolInfo;

/// A symbol.
pub enum Content<'d> {
    /// A message.
    Message(super::message::Message<'d>),

    /// An enum.
    Enum(super::enum_::Enum<'d>),
}

/// Implements [`std::fmt::Debug`] for [`Content`].
impl std::fmt::Debug for Content<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Message(msg) => write!(f, "Message{{{msg:?}}}"),
            Self::Enum(e) => write!(f, "Enum{{{e:?}}}"),
        }
    }
}

/// A symbol.
#[derive(Debug)]
pub struct Symbol<'d> {
    /// Symbol's information.
    pub(crate) info: SymbolInfo<'d>,

    /// Information about the file it comes from.
    pub(crate) file_info: FileInfo<'d>,

    /// Symbol's content.
    pub(crate) content: Content<'d>,
}

/// Instantiates a [`Symbol`] from a message descriptor and a file info.
impl<'d> std::convert::TryFrom<(FileInfo<'d>, &'d protobuf::descriptor::DescriptorProto)>
    for Symbol<'d>
{
    type Error = String;

    fn try_from(
        (file_info, descriptor): (FileInfo<'d>, &'d protobuf::descriptor::DescriptorProto),
    ) -> Result<Self, Self::Error> {
        let name = descriptor
            .name
            .as_deref()
            .ok_or("message symbol does not have a name")?;
        Ok(Self {
            info: SymbolInfo::from(name),
            file_info,
            content: Content::Message(super::message::Message::try_from(descriptor)?),
        })
    }
}

/// Instantiates a [`Symbol`] from an enum descriptor and a file info.
impl<'d> std::convert::TryFrom<(FileInfo<'d>, &'d protobuf::descriptor::EnumDescriptorProto)>
    for Symbol<'d>
{
    type Error = String;

    fn try_from(
        (file_info, descriptor): (FileInfo<'d>, &'d protobuf::descriptor::EnumDescriptorProto),
    ) -> Result<Self, Self::Error> {
        let name = descriptor
            .name
            .as_deref()
            .ok_or("enum symbol does not have a name")?;
        Ok(Self {
            info: SymbolInfo::from(name),
            file_info,
            content: Content::Enum(super::enum_::Enum::try_from(descriptor)?),
        })
    }
}

/// Implements [`Symbol`].
impl<'d> Symbol<'d> {
    /// Returns the symbol's information.
    pub fn info(&self) -> &SymbolInfo<'d> {
        &self.info
    }

    /// Returns the information about the file owning the symbol.
    pub fn file_info(&self) -> &FileInfo<'d> {
        &self.file_info
    }

    /// Returns the content of the symbol.
    pub fn content(&self) -> &Content<'d> {
        &self.content
    }

    /// Returns true if the symbol is a message.
    pub fn is_message(&self) -> bool {
        matches!(self.content, Content::Message(_))
    }

    /// Returns true if the symbol is an enum.
    pub fn is_enum(&self) -> bool {
        matches!(self.content, Content::Enum(_))
    }
}

#[cfg(test)]
mod test {
    /// Tests [`super::Symbol`] constructor with a message.
    #[test]
    fn test_symbol_constructor_message() {
        let mut fdesc = protobuf::descriptor::FileDescriptorProto::new();
        let file_info = crate::file_info::test::valid_info(&mut fdesc);

        let mut mdesc = protobuf::descriptor::DescriptorProto::new();

        mdesc.name = Some("n4m3".into());
        let sym = super::Symbol::try_from((file_info.clone(), &mdesc)).expect("constructor failed");

        assert!(!sym.is_enum());
        assert!(sym.is_message());
        assert_eq!(sym.info().name(), "n4m3");
        assert!(matches!(sym.content(), super::Content::Message(_)));
    }

    /// Tests [`super::Symbol`] constructor with a message that has no name.
    #[test]
    fn test_symbol_constructor_message_missing_name() {
        let mut fdesc = protobuf::descriptor::FileDescriptorProto::new();
        let file_info = crate::file_info::test::valid_info(&mut fdesc);

        let mut mdesc = protobuf::descriptor::DescriptorProto::new();

        mdesc.name = None;
        super::Symbol::try_from((file_info.clone(), &mdesc))
            .expect_err("constructor succeed, but it should have failed");
    }

    /// Tests [`super::Symbol`] constructor with an enum.
    #[test]
    fn test_symbol_constructor_enum() {
        let mut fdesc = protobuf::descriptor::FileDescriptorProto::new();
        let file_info = crate::file_info::test::valid_info(&mut fdesc);

        let mut edesc = protobuf::descriptor::EnumDescriptorProto::new();

        edesc.name = Some("3num".into());
        let sym = super::Symbol::try_from((file_info.clone(), &edesc)).expect("constructor failed");

        assert!(sym.is_enum());
        assert!(!sym.is_message());
        assert_eq!(sym.info().name(), "3num");
        assert!(matches!(sym.content(), super::Content::Enum(_)));
    }

    /// Tests [`super::Symbol`] constructor with an enum that has no name.
    #[test]
    fn test_symbol_constructor_enum_missing_name() {
        let mut fdesc = protobuf::descriptor::FileDescriptorProto::new();
        let file_info = crate::file_info::test::valid_info(&mut fdesc);

        let mut edesc = protobuf::descriptor::EnumDescriptorProto::new();

        edesc.name = None;
        super::Symbol::try_from((file_info.clone(), &edesc))
            .expect_err("constructor succeed, but it should have failed");
    }
}
