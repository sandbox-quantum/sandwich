// Copyright 2023 SandboxAQ
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Define [`DataSource`] struct.
//!
//! A [`DataSource`] struct provides a way to retrieve materials from various
//! sources. The source is given by the protobuf configuration (see
//! [`api_rust_proto::DataSource`].
//!
//! Author: aguinetsb & thb-sb

use pb::DataSourceError::*;

/// A DataSource.
/// Source of the material is either from the local filesystem (`Fs`), from
/// an inline slice of bytes (`Bytes`) or from a inline string (`String`).
/// The content is borrowed, unless is it explicitly mandated to own it.
pub(crate) enum DataSource<'data> {
    Fs(std::vec::Vec<u8>),
    Bytes(std::borrow::Cow<'data, [u8]>),
    String(std::borrow::Cow<'data, str>),
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
impl<'ds: 'data, 'data> std::convert::TryFrom<&'ds pb_api::DataSource> for DataSource<'data> {
    type Error = crate::Error;
    fn try_from(ds: &'ds pb_api::DataSource) -> crate::Result<DataSource<'data>> {
        use pb_api::data_source::data_source;
        ds.specifier
            .as_ref()
            .ok_or_else(|| DATASOURCEERROR_INVALID_CASE.into())
            .and_then(|oneof| match oneof {
                data_source::Specifier::Filename(path) => Ok(Self::Fs(
                    std::fs::read(path).or(Err(DATASOURCEERROR_NOT_FOUND))?,
                )),
                data_source::Specifier::InlineBytes(ref v) => {
                    Ok(Self::Bytes(std::borrow::Cow::from(v)))
                }
                data_source::Specifier::InlineString(ref v) => {
                    Ok(Self::String(std::borrow::Cow::from(v)))
                }
                _ => Err(DATASOURCEERROR_INVALID_CASE.into()),
            })
    }
}

/// Returns the data holds by the [`DataSource`] as a slice of bytes.
impl<'data> std::convert::AsRef<[u8]> for DataSource<'data> {
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
impl<'data> std::convert::From<&DataSource<'data>> for *const std::ffi::c_void {
    fn from(ds: &DataSource<'data>) -> Self {
        (unsafe { ds.as_raw() }) as Self
    }
}

/// Implements [`DataSource`].
impl<'data> DataSource<'data> {
    /// Returns the len of the data.
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
    use super::super::pb;
    use super::DataSource;

    /// Path to an existing and readable file.
    const FILE_PATH: &str = "testdata/key.pem";

    /// Tests [`DataSource`] constructor from a protobuf `DataSource` message
    /// containing a file path.
    #[test]
    fn test_datasource_constructor_fs() {
        let mt = std::fs::metadata(FILE_PATH);
        assert!(mt.is_ok());
        let fsize = mt.unwrap().len() as usize;

        let mut ds = pb_api::DataSource::new();
        ds.set_filename(FILE_PATH.to_string());
        let ds = DataSource::try_from(&ds);
        assert!(ds.is_ok());
        let ds = ds.unwrap();
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
