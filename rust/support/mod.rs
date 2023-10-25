// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Sandwich support module.

#![allow(unused_imports)]
#![allow(dead_code)]

mod data_source;
mod pimpl;

pub(crate) use data_source::DataSource;
pub(crate) use pimpl::Pimpl;

/// Checks if a given string contains any of the characters from another string.
pub(crate) fn contains_any_of(string: &str, invalid_chars: &str) -> bool {
    string.chars().any(|c| invalid_chars.contains(c))
}

/// Joins the strings together with the delimiter in between each string.
pub(crate) fn join_strings_with_delimiter(
    strings: std::slice::Iter<'_, impl AsRef<str>>,
    delimiter: char,
) -> String {
    let mut output = String::new();
    for s in strings {
        output.push_str(s.as_ref());
        output.push(delimiter);
    }
    output.pop();
    output
}

/// Builds ciphersuite string with delimiter from list of ciphersuites.
/// Return Error if contain any of the characters from the `invalid_chars`.
pub(crate) fn build_ciphersuites_list(
    ciphers: std::slice::Iter<'_, impl AsRef<str>>,
    invalid_chars: &str,
) -> Result<String, crate::Error> {
    let mut output = String::new();
    for c in ciphers {
        if contains_any_of(c.as_ref(), invalid_chars) {
            return Err(
                pb::TLSConfigurationError::TLSCONFIGURATIONERROR_UNSUPPORTED_CONTROL_CHARACTERS
                    .into(),
            );
        }
        output.push_str(c.as_ref());
        output.push(':');
    }
    output.pop();
    Ok(output)
}
