///! Defines [`Info`].
///!
///! [`Info`] describes a protobuf source file, using its package name
///! and its file path.
extern crate protobuf;

use super::source_info::Info as SourceInfo;

/// File information.
#[derive(Clone)]
pub struct Info<'s> {
    /// The package name.
    pub package_name: &'s str,

    /// The file name.
    pub file_name: &'s str,

    /// Content of the file.
    /// This is a vector that contains each line of the file.
    pub content: std::rc::Rc<Vec<String>>,

    /// Information about the source file.
    pub source_info: std::rc::Rc<SourceInfo<'s>>,
}

/// Implements [`std::fmt::Display`] for [`Info`].
impl std::fmt::Debug for Info<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Info(package = {}, filename = {}, source_info = {:?})",
            self.package_name, self.file_name, self.source_info,
        )
    }
}

/// Instantiates a [`Info`] from a [`protobuf::descriptor::FileDescriptorProto`].
impl<'s> std::convert::TryFrom<&'s protobuf::descriptor::FileDescriptorProto> for Info<'s> {
    type Error = String;

    fn try_from(fd: &'s protobuf::descriptor::FileDescriptorProto) -> Result<Self, Self::Error> {
        let package_name = fd
            .package
            .as_ref()
            .ok_or_else(|| format!("file {fd:?} does not have a package"))?;

        let file_name = fd
            .name
            .as_ref()
            .ok_or_else(|| format!("file {fd:?} does not have a name"))?;

        let source_info = fd
            .source_code_info
            .as_ref()
            .ok_or_else(|| format!("file {fd:?} does not have any source code info"))?;

        let file = std::fs::File::open(file_name)
            .map_err(|e| format!("failed to open {file_name}: {e}"))?;
        let lines = <_ as std::io::BufRead>::lines(std::io::BufReader::new(file));

        let mut ls = Vec::<String>::new();

        for l in lines {
            let l = l.map_err(|e| format!("failed to read line: {e}"))?;
            ls.push(l);
        }

        Ok(Self {
            package_name,
            file_name,
            content: ls.into(),
            source_info: SourceInfo::try_from(source_info)?.into(),
        })
    }
}

#[cfg(test)]
pub(crate) mod test {
    /// Returns a valid [`super::Info`].
    pub(crate) fn valid_info<'d>(
        desc: &'d mut protobuf::descriptor::FileDescriptorProto,
    ) -> super::Info<'d> {
        desc.name = Some(crate::test::TEST_PROTO_PATH.into());
        desc.package = Some("com.example.proto".into());
        desc.source_code_info =
            protobuf::MessageField(Some(Box::new(protobuf::descriptor::SourceCodeInfo::new())));

        super::Info::try_from(&*desc).expect("constructor failed")
    }

    /// Tests the constructor of [`super::Info`] with a descriptor that doesn't
    /// have a name or a package.
    #[test]
    fn test_info_constructor_missing_name_package() {
        let mut desc = protobuf::descriptor::FileDescriptorProto::new();

        super::Info::try_from(&desc).expect_err("constructor succeed, but should have failed");

        desc.name = Some(crate::test::TEST_PROTO_PATH.into());
        super::Info::try_from(&desc).expect_err("constructor succeed, but should have failed");

        desc.package = Some("com.example.proto".into());
        desc.source_code_info =
            protobuf::MessageField(Some(Box::new(protobuf::descriptor::SourceCodeInfo::new())));
        super::Info::try_from(&desc).expect("constructor failed");
    }

    /// Tests the constructor of [`super::Info`] with an invalid file_name.
    #[test]
    fn test_info_constructor_invalid_file_name() {
        let mut desc = protobuf::descriptor::FileDescriptorProto::new();
        desc.name = Some("invalid/file/path".into());
        desc.package = Some("com.example.proto".into());
        desc.source_code_info =
            protobuf::MessageField(Some(Box::new(protobuf::descriptor::SourceCodeInfo::new())));
        super::Info::try_from(&desc).expect_err("constructor succeed, but should have failed");

        desc.name = Some(crate::test::TEST_PROTO_PATH.into());
        super::Info::try_from(&desc).expect("constructor failed");
    }

    /// Tests the constructor of [`super::Info`].
    #[test]
    fn test_info_constructor() {
        let mut desc = protobuf::descriptor::FileDescriptorProto::new();
        desc.name = Some(crate::test::TEST_PROTO_PATH.into());
        desc.package = Some("com.example.proto".into());
        desc.source_code_info =
            protobuf::MessageField(Some(Box::new(protobuf::descriptor::SourceCodeInfo::new())));

        let file_info = super::Info::try_from(&desc).expect("constructor failed");

        assert_eq!(file_info.package_name, "com.example.proto");
        assert_eq!(file_info.file_name, crate::test::TEST_PROTO_PATH);
    }

    /// Tests the content of [`super::Info`].
    #[test]
    fn test_info_content() {
        let lines = {
            let file =
                std::fs::File::open(crate::test::TEST_PROTO_PATH).expect("failed to open file");
            let lines = <_ as std::io::BufRead>::lines(std::io::BufReader::new(file));
            let mut ls = Vec::<String>::new();
            for l in lines {
                let l = l.expect("failed to read line");
                ls.push(l);
            }
            ls
        };

        let mut desc = protobuf::descriptor::FileDescriptorProto::new();
        desc.name = Some(crate::test::TEST_PROTO_PATH.into());
        desc.package = Some("com.example.proto".into());
        desc.source_code_info =
            protobuf::MessageField(Some(Box::new(protobuf::descriptor::SourceCodeInfo::new())));

        let file_info = super::Info::try_from(&desc).expect("constructor failed");
        assert_eq!(*file_info.content, lines);
    }
}
