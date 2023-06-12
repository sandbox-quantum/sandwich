///! Defines [`Info`].
///!
///! [`Info`] is a structure that collects various information about a
///! symbol, such as its name, its source code and its comments (if any).
extern crate protobuf;

use super::source_info::Comments;

/// A symbol information.
pub struct Info<'d> {
    /// The symbol's name.
    pub(crate) name: &'d str,

    /// Symbol's source code, if any.
    /// Each element of the vector is a line.
    pub(crate) source: Vec<String>,

    /// Symbol's comments.
    pub(crate) comments: Option<Comments<'d>>,
}

/// Implements [`std::fmt::Debug`] for [`Info`].
impl std::fmt::Debug for Info<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            r#"Info{{
    .name = {name},
    .source = {len_lines} line(s),
    .comments = {comments:?},
    }}"#,
            name = self.name(),
            len_lines = self.source.len(),
            comments = self.comments,
        )
    }
}

/// Instantiates a [`Info`] from a name.
impl<'d> std::convert::From<&'d str> for Info<'d> {
    fn from(name: &'d str) -> Self {
        Self {
            name,
            source: Vec::new(),
            comments: None,
        }
    }
}

/// Implements [`Info`].
impl<'d> Info<'d> {
    /// Returns the symbol's name.
    pub fn name(&self) -> &'d str {
        self.name
    }

    /// Returns the symbol's source code.
    pub fn source(&self) -> &[String] {
        &self.source[..]
    }

    /// Returns the comments.
    pub fn comments(&self) -> Option<&Comments<'d>> {
        self.comments.as_ref()
    }
}

#[cfg(test)]
mod test {
    /// Tests [`super::Info`] constructor.
    #[test]
    fn test_info_constructor() {
        let sym_info = super::Info::from("n4m3");
        assert_eq!(sym_info.name(), "n4m3");
        assert!(sym_info.source().is_empty());
        assert!(sym_info.comments().is_none());
    }
}
