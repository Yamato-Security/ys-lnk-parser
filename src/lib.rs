// Copyright (C) 2026 Shirofune Security Co., Ltd.
// Copyright (c) 2026 Cyber Experts
//
// This file is changed from Sootmark/shell (https://github.com/Sootmark/shell), whose code is under
// the MIT License or the Apache License 2.0 (LICENSE-MIT, LICENSE-APACHE).
//
// Unless explicitly acquired and licensed from Licensor under another license, the contents of this
// file are subject to the Reciprocal Public License ("RPL") Version 1.5, or subsequent versions as
// allowed by the RPL, and You may not copy or use this file in either source code or executable
// form, except in compliance with the terms and conditions of the RPL.
//
// All software distributed under the RPL is provided strictly on an "AS IS" basis, WITHOUT WARRANTY
// OF ANY KIND, EITHER EXPRESS OR IMPLIED, AND LICENSOR HEREBY DISCLAIMS ALL SUCH WARRANTIES,
// INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
// PURPOSE, QUIET ENJOYMENT, OR NON-INFRINGEMENT. See the RPL for specific language governing rights
// and limitations under the RPL.

//! Windows shell data: shell items ([`item`]), the building blocks of
//! ShellBags, LNK files and jump lists; LNK files ([`lnk`]); jump lists
//! ([`jumplist`]) and the compound files they're stored in ([`compound`]).
//!
//! Written from the public documentation: libyal's "Windows Shell Item
//! format" and "Jump lists format", Microsoft's MS-SHLLINK, MS-PROPSTORE and
//! MS-CFB. No dependencies by default (the `codepages` feature adds
//! `encoding_rs` for code pages other than Windows-1252); every read is
//! bounds-checked and damage is reported, never a panic.

pub mod codepage;
pub mod compound;
pub mod guid_names;
pub mod item;
pub mod jumplist;
pub mod lnk;
pub mod property;

/// This crate's version, for provenance.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub(crate) fn u16_at(data: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        data.get(at..at.checked_add(2)?)?.try_into().ok()?,
    ))
}

pub(crate) fn u32_at(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        data.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

pub(crate) fn u64_at(data: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        data.get(at..at.checked_add(8)?)?.try_into().ok()?,
    ))
}
