# Changelog

## 1.0.0 (Unreleased)

### Changed
- The crate is named after its repository, `ys-lnk-parser` (its library is still `shell`: depend on
  it as `shell = { package = "ys-lnk-parser", … }`), version 1.0.0, by Florian Amette and Zach
  Mathis (@yamatosecurity), on Rust's 2024 edition, and requires Rust 1.99 (also with
  `codepages`). (@YamatoSecurity)

### Added
- `item::Kind::CdBurn`: a file or folder staged for burning to a CD or DVD (an `AugM` item), named
  from the file entry it wraps, with its times and NTFS reference. It was an unknown class 0 item,
  and a target path ended at the drive (`This PC\D:\` for `This PC\D:\autorun.inf`).
  (@YamatoSecurity)

### Fixed
- A library's folder (a property view item) has the times and NTFS reference of the folder it
  holds the path of (the last file entry of its property 32 item list), where a target's MFT
  entry is taken from: a jump list entry for a library folder had none.
  (@YamatoSecurity)

## 0.4.0 (ys-lnk-parser)

First version of Yamato Security's fork, based on sootmark-shell 0.3.0 (Sootmark/shell dc16337).
(@YamatoSecurity)

### Added
- Links: the header's icon index, show command and hotkey (`show_command_name`, `hotkey_name`),
  undefined flag bits (`unknown_flags`); every extra data block: console properties
  (`Console`), the console's code page, the Darwin identifier, the icon environment target, known
  folder (GUID and item offset), special folder (CSIDL, `special_folder_name`), property store
  (`properties`), shim layer, VistaAndAboveIDList (`vista_target`, `vista_target_path`), and the
  tracker's birth droids with their MAC address and time; the network share's mapped drive and
  provider (`network_device`, `network_provider`, `network_provider_name`).
- `Link::problems`: what's damaged or unusual (a section running past the end, a truncated block,
  no terminal block, capped string data).
- A command line hidden behind an over-long name, relative path or working directory is read as
  Windows reads it (260 characters each) when the counts run past the file.
- `property`: serialized property stores (MS-PROPSTORE).
- `codepage` and `lnk::parse_with` / `item::decode_with`: text that isn't Unicode in a code page;
  the `codepages` feature (`encoding_rs`) for code pages other than Windows-1252.
- `guid_names` (default feature `guid-names`): names of shell GUIDs from a GUID name table (MIT),
  used for root folders, known folders and control panel pages the crate
  didn't name.
- Tests on LnkParse3's 34 links and its output, and on links built in the tests.

### Changed
- Windows-1252 text is decoded as Windows-1252 (it was Latin-1).
- Target paths drop a network item's leading backslashes after the first item.
- Compound file entries' times are FILETIMEs (`Option<u64>`); `Link` and the jump list types are
  no longer `Eq` (property values may be floating point).
- No dependencies by default (`sootmark-common` is gone). Not published (`publish = false`); MSRV
  1.80 (1.88 with `codepages`); CI on Linux, macOS and Windows with the actions pinned by commit;
  no toolchain pin.

### Fixed
- A damaged property storage size in a property view item made parsing loop forever.
- A file entry whose Unicode short name isn't NUL-terminated (Windows XP) lost its long name: the
  extension block is found from the offset at the item's end.
- LinkInfo, VolumeID and CommonNetworkRelativeLink offsets into their structure's header were read
  as text (a common path suffix offset of 0 appended the LinkInfo size's low byte to the path).
- A time and MAC address were read from tracker and DestList GUIDs of any version; only version 1
  GUIDs have them.
- Delegate items nested thousands deep overflowed the stack.
- DestList entries repeating a stream made a copy of its link each.
