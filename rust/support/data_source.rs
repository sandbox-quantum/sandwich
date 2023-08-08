// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! A source of data.
//!
//! [`DataSource`] provides a way to retrieve materials from various
//! sources. The source is given by the protobuf configuration (see
//! [`crate::pb_api::DataSource`].
//!
//! ## Example
//!
//! ### Using a file stored on the local filesystem.
//!
//! ```no_run
//! use crate::pb_api;
//! use DataSource;
//!
//! pb_api::DataSource
//! ```

use crate::{Error, Result};
use std::borrow::Cow;

/// A source of data.
///
/// Source of the material is either from the local filesystem (`Fs`), from
/// an inline slice of bytes (`Bytes`) or from a inline string (`String`).
/// The content is borrowed, unless is it explicitly mandated to own it.
pub(crate) enum DataSource<'data> {
    Fs(Vec<u8>),
    Bytes(Cow<'data, [u8]>),
    String(Cow<'data, str>),
}

/// Instantiates a [`DataSource`] from a protobuf `DataSource` message.
///
/// # Errors
///
/// If the protobuf `DataSource` message provides a filename, and the file
/// couldn't be found or read from the local filesystem, then
/// `DataSourceError::DATASOURCEERROR_NOT_FOUND` is returned.
///
/// If the protobuf `DataSource` message doesn't provide any source type,
/// then `DataSourceError::DATASOURCEERROR_INVALID_CASE` is returned.
impl<'ds: 'data, 'data> TryFrom<&'ds pb_api::DataSource> for DataSource<'data> {
    type Error = Error;

    fn try_from(ds: &'ds pb_api::DataSource) -> Result<DataSource<'data>> {
        use pb::DataSourceError;
        use pb_api::data_source::data_source;
        ds.specifier
            .as_ref()
            .ok_or_else(|| DataSourceError::DATASOURCEERROR_INVALID_CASE.into())
            .and_then(|oneof| match oneof {
                data_source::Specifier::Filename(path) => Ok(Self::Fs(
                    std::fs::read(path).or(Err(DataSourceError::DATASOURCEERROR_NOT_FOUND))?,
                )),
                data_source::Specifier::InlineBytes(ref v) => Ok(Self::Bytes(Cow::from(v))),
                data_source::Specifier::InlineString(ref v) => Ok(Self::String(Cow::from(v))),
                _ => Err(DataSourceError::DATASOURCEERROR_INVALID_CASE.into()),
            })
    }
}

/// Returns the data holds by the [`DataSource`] as a slice of bytes.
impl<'data> AsRef<[u8]> for DataSource<'data> {
    fn as_ref(&self) -> &[u8] {
        match *self {
            DataSource::Fs(ref v) => v,
            DataSource::Bytes(ref b) => b,
            DataSource::String(ref s) => s.as_bytes(),
        }
    }
}

/// Implements [`std::fmt::Debug`] for [`DataSource`].
impl<'data> std::fmt::Debug for DataSource<'data> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            DataSource::Fs(ref v) => write!(f, "DataSource::Fs({} byte(s))", v.len()),
            DataSource::Bytes(ref b) => write!(f, "DataSource::Bytes({} byte(s))", b.len()),
            DataSource::String(ref s) => write!(f, "DataSource::String({} byte(s))", s.len()),
        }
    }
}

/// Get the raw void pointer to the data held by the `DataSource`.
///
/// **WARNING**: because the returned value is a raw pointer, we cannot
/// enforce `DataSource` to outlive this returned pointer.
impl<'data> From<&DataSource<'data>> for *const std::ffi::c_void {
    fn from(ds: &DataSource<'data>) -> Self {
        (unsafe { ds.as_raw() }) as Self
    }
}

/// Implements [`DataSource`].
impl<'data> DataSource<'data> {
    /// Returns the len of the data.
    #[allow(dead_code)]
    pub fn len(&'data self) -> usize {
        self.as_ref().len()
    }

    /// Returns a pointer to the underlying data.
    ///
    /// This function is unsafe, as we cannot enforce `DataSource` to outlive
    /// the returned pointer.
    pub unsafe fn as_raw(&self) -> *const u8 {
        self.as_ref().as_ptr()
    }
}

/// Tests for [`DataSource`].
#[cfg(test)]
mod test {
    use super::DataSource;

    /// Path to an existing and readable file.
    const FILE_PATH: &str = "testdata/dilithium5.cert.pem";

    /// Tests [`DataSource`] constructor from a protobuf `DataSource` message
    /// containing a file path.
    #[test]
    fn test_datasource_constructor_fs() {
        let filepath = crate::test::resolve_runfile(FILE_PATH);
        let mt = std::fs::metadata(&filepath);
        assert!(mt.is_ok());
        let fsize = mt.unwrap().len() as usize;

        let mut ds = pb_api::DataSource::new();
        ds.set_filename(filepath);
        let ds = DataSource::try_from(&ds).unwrap();
        assert_eq!(ds.len(), fsize);
    }

    /// Tests [`DataSource`] constructor from a protobuf `DataSource` message
    /// containing a path to a non-existent file.
    #[test]
    fn test_datasource_constructor_bad_fs_path() {
        let mut ds = pb_api::DataSource::new();
        ds.set_filename("/non/existent/file".to_string());
        let ds = DataSource::try_from(&ds);
        assert!(ds.is_err());
        assert!(ds.unwrap_err().is(&errors! {
            pb::DataSourceError::DATASOURCEERROR_NOT_FOUND
        }));
    }

    /// Tests [`DataSource`] constructor from a protobuf [`DataSource`] message
    /// containing bytes.
    #[test]
    fn test_datasource_constructor_bytes() {
        let data = vec![0u8, 1u8, 2u8, 3u8, 4u8, 5u8];

        let mut ds = pb_api::DataSource::new();
        ds.set_inline_bytes(data.clone());

        let ds = DataSource::try_from(&ds);
        assert!(ds.is_ok());
        let ds = ds.unwrap();
        assert_eq!(ds.len(), data.len());
        assert_eq!(ds.as_ref(), data);
    }

    /// Tests [`DataSource`] constructor from a protobuf `DataSource` message
    /// containing a string.
    #[test]
    fn test_datasource_constructor_string() {
        let s = ":sandwich-intensifies:";

        let mut ds = pb_api::DataSource::new();

        ds.set_inline_string(s.to_string());

        let ds = DataSource::try_from(&ds);
        assert!(ds.is_ok());
        let ds = ds.unwrap();
        assert_eq!(ds.len(), s.len());
        assert_eq!(ds.as_ref(), s.as_bytes());
    }
}
