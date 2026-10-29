# ys-lnk-parser

Yamato Security's maintained fork of [sootmark-shell](https://github.com/Sootmark/shell) (Florian
Amette): Windows shell link (`.lnk`) files, shell items, jump lists and the compound files they're
stored in, used by [Juntei](https://github.com/Yamato-Security/juntei)'s `parse-lnk`. The upstream
history and the MIT OR Apache-2.0 license are kept; everything below the line is upstream's README,
updated for what the fork changed.

sootmark-shell was chosen after running the Rust LNK parsers on 1,123 real links (Eric Zimmerman's
test set from Windows XP to 10, DFIRArtifactMuseum, LnkParse3's, plaso's and the crates' own test
links, and the links in DFIRArtifactMuseum's jump lists) against pylnk (libyal), LnkParse3 and
LECmd 2026.10 (built from source), which agree on every field once their representations are
aligned, and on 45,000 damaged copies:

| Crate | Read | Fields that differ from the references | Damaged links: panics / allocations over 1 GiB / hangs | Notes |
| --- | --- | --- | --- | --- |
| **sootmark-shell 0.3.0** | 1,119 | a suffix and a MAC address on crafted links; 26 target paths | 0 / 0 / 1 | best shell item names, jump lists and compound files, tests against LECmd and JLECmd; 2 of 11 extra data blocks |
| lnk-core 0.4.1 (SecurityRonin) | 1,119 | target times wrong in 744 links; non-ASCII ANSI text garbled | 0 / 0 / 0 | Apache-2.0; only the tracker block |
| lnk_parser 0.4.3 | 1,111 | volume serials unpadded | 0 / 730 / 0 | only the tracker block |
| lnk 0.6.4 (lnk-rs) | 1,024 | NUL padding left in strings | 0 / 46 / 0 | reads from a path only |
| rclip-shell-link 0.1.0 | | (review: agrees on the fields compared) | (review: 0 / 0 / 0) | every block, but a damaged section discards the whole file; no LICENSE files |
| parselnk 0.1.1, lnks 0.2.0 | | | | not maintained since 2022 / Windows COM only |

What the fork adds and fixes:

| Change | Source |
| --- | --- |
| A damaged property storage size in a property view item made parsing loop forever | fork (fuzzing) |
| A Windows XP item whose Unicode short name isn't NUL-terminated lost its long name (`ÉchantillB…뻯ㄔ…`): the extension block is now found from the offset at the item's end | fork; as libyal and LECmd |
| LinkInfo offsets into the header read the header as text (`E:\payload.exeH`) | fork |
| A time and MAC address only from version 1 GUIDs | fork |
| Delegate items nesting thousands deep overflowed the stack; DestList entries repeating a stream made a copy of its link each (a 90 KB jump list reached 853 MiB) | fork (review) |
| The header's icon index, show command and hotkey; every extra data block (console, console code page, Darwin, icon environment, known and special folders, property store, shim, Vista ID list, the tracker's birth droids); the network share's drive and provider | written from MS-SHLLINK; checked against LnkParse3's output |
| Property stores (MS-PROPSTORE): numbered and named properties, typed values, canonical names | written from MS-PROPSTORE |
| A command line hidden behind an over-long working directory: read as Windows reads it (260 characters), as LnkParse3 does | idea of LnkParse3 |
| `Link::problems`: what's damaged or unusual, the parse going on where it can | fork |
| Windows-1252 decoded as Windows-1252 (it was Latin-1); other code pages, Shift-JIS for Japanese systems among them, with the `codepages` feature | fork; code page idea of lnk-rs and LECmd |
| GUIDs named from Eric Zimmerman's GuidMapping table (MIT): Network, Computers and Devices, control panel pages, … | EZ's GuidMapping |
| No dependencies by default (`sootmark-common` replaced) | fork |
| Tests on LnkParse3's 34 links and its output (MIT) | fork |

On the 1,118 links the three references all read, every field of the header, link info, string
data and tracker block equals theirs, the icon index, show command, hotkey and birth droids
included, and 1,105 target paths equal LECmd's. Of the 13 that differ, LECmd shows a damaged item
or cuts a name in 4 and a placeholder (`(None)`, `No Property sheet value found`) in 6, and names an
MTP device or control panel applet the fork doesn't in 3. 67,000 damaged copies parse without a panic, an
allocation over 1 GiB or a hang.

```rust
// a link from a Japanese system (feature "codepages")
let link = shell::lnk::parse_with(&std::fs::read("report.lnk")?, &shell::lnk::Options { code_page: 932 })?;
println!("{} {} {:?}", link.target_path(), link.arguments, link.problems);
for p in &link.properties {
    println!("{} = {}", p.canonical_name().unwrap_or("?"), p.value.display());
}
```

Use it from Cargo by commit (the crate is `ys-lnk-parser`, named after the repository, and its
library keeps the name `shell`; it is not published, and its versions are the fork's own: 1.0.0
since the rename; Rust 1.99 and edition 2024):

```toml
shell = { package = "ys-lnk-parser", git = "https://github.com/Yamato-Security/ys-lnk-parser", rev = "<commit>", features = ["codepages"] }
```

Not yet: MTP device and storage items and control panel applet (`.cpl`) items (3 of the test
links); decoding the Darwin descriptor into the Windows Installer product and component codes.

---

# shell

Windows shell data, written from the public documentation (libyal's "Windows Shell Item format" and "Jump lists format", Microsoft's MS-SHLLINK, MS-PROPSTORE and MS-CFB): shell items, the building blocks of ShellBags, LNK files and jump lists; LNK files; property stores; jump lists; and the compound files automatic jump lists are stored in. No dependencies by default; the `codepages` feature adds `encoding_rs` for code pages other than Windows-1252, and the default `guid-names` feature names GUIDs from Eric Zimmerman's GuidMapping table.

```toml
[dependencies]
shell = { package = "ys-lnk-parser", git = "https://github.com/Yamato-Security/ys-lnk-parser", rev = "<commit>" }
```

```rust
let link = shell::lnk::parse(&std::fs::read("report.docx.lnk")?)?;
println!("{} ({})", link.local_path, link.target_path());
if let Some(tracker) = &link.tracker {
    println!("made on {} ({})", tracker.machine_id, tracker.mac);
}

// What Explorer (AppID f01b4d95cf55d32a) offered in its taskbar menu.
let list = shell::jumplist::automatic(&std::fs::read("f01b4d95cf55d32a.automaticDestinations-ms")?)?;
for d in &list.destinations {
    println!("{} used {} times, pinned: {}", d.path, d.access_count.unwrap_or(0), d.pin.is_some());
}
```

## What you get

- `lnk::parse` (`parse_with` for another code page): the target's times, size and attributes as they were when the link was saved; the icon index, show command and hotkey; its shell items (`target_path()`), volume (type, serial number, label), local path, network share (with the drive it was mapped to and the provider), string data (name, relative path, working directory, arguments, icon; a command line hidden behind an over-long field read as Windows reads it), and every extra data block: the environment-variable and icon environment targets, the tracker block (machine name, volume and object identifiers now and at birth, the MAC address and creation time in a version 1 object identifier), known and special folders, the property store (`property`), console properties and code page, the Darwin identifier, the shim layer, the Vista ID list; and `problems`, what's damaged or unusual about the file.
- `property`: serialized property stores (MS-PROPSTORE): numbered and named properties with their typed values, and the canonical names of well-known ones (`System.Link.TargetParsingPath`, `System.AppUserModel.ID`, …).
- `codepage`: text in a Windows code page (Windows-1252 built in, others with the `codepages` feature). `guid_names`: names of shell GUIDs.
- `jumplist::automatic`: each `DestList` entry (entry number, last use, pin position, access count on Windows 10 and later, machine name, the tracker's volume and file identifiers now and at birth, with the time and MAC address in the file identifier, the recorded path) and its link, most recent first. `jumplist::custom`: the categories an application defined (named, frequent or recent, tasks) and their links.
- `compound`: compound files (OLE, MS-CFB): the directory, each entry with its creation and modification times, its parent storage and its path from the root (`Root Entry/\u{5}SummaryInformation`), and any stream, from either sector size, mini streams included. Every chain and count is bounded by the file: a looping or truncated table is an error, not a hang or a huge allocation. The directory tree is walked once per entry: a link to a missing entry, a loop, or an entry the root doesn't reach is a problem, and the rest still reads.
- `item`: shell items (root and known folders, drives, folders and files with their long names, FAT times and NTFS references, control panel pages and categories, "Users Files" delegates, property views (apps under Applications included, library folders with their folder's times and NTFS reference), files and folders staged for a CD or DVD burn, network locations, URIs). Other classes are reported as unknown with their class byte, not guessed. Root and known folders are named as Eric Zimmerman's tools name them.

## How it's checked

- Eric Zimmerman's LNK test set (MIT; `tests/fixtures/EZ-LICENSE.txt`, which also covers his jump lists): 552 links from Windows XP to 10, every column LECmd reports compared (times, size, attributes, flags, volume, local and network paths, strings, machine, MAC, tracker time, MFT reference, extra blocks, target path); where LECmd shows a localized resource string, a short name or garbled text in a path, the difference is documented in `tests/lnk.rs`. The damaged file is refused.
- Jump lists against JLECmd: Eric Zimmerman's test set (MIT; Windows 7, 8.0, 8.1 and 10), plaso's (Apache-2.0; `tests/fixtures/jumplist/plaso/LICENSE-plaso.txt`) and a synthetic custom list; 31 `DestList` entries on every column (entry, order, times, machine, MAC, counts, pins, the four identifiers, path) with their links, and 17 custom links. JLECmd names only the first category of a custom list; the others are checked by hand in `tests/jumplist.rs`.
- Compound files against olefile (BSD-licensed, run as an oracle, not part of the crate; `tests/fixtures/oracle/olefile_tree.py`): every directory entry's path, type, size, creation and modification time in plaso's `Document.doc` (a storage within a storage) and the eight automatic jump lists, 57 entries (`tests/compound.rs`).
- LnkParse3's 34 test links and its output (MIT, Matúš Jasnický; `tests/fixtures/lnkparse3/`): every field both read (header, string data, link info, every extra data block LnkParse3 decodes, data after the terminal block) agrees, the command line hidden behind padding included (`tests/lnkparse3.rs`).
- Links built in the tests for what the sets don't vary: damaged offsets, version 1 and other GUIDs, header fields, shim, property store and Vista blocks, a Shift-JIS string (`tests/built.rs`); delegate items nested 6,000 deep, CD burn items (one from a jump list, one of Eric Zimmerman's samples) and burn items nested as deep as an item allows, a library folder holding the items of a real link, and a DestList repeating one stream 200 times.
- Corrupted and truncated links, jump lists and compound files, and arbitrary bytes (property tests): parsed or refused, never a panic.

## Licence

MIT or Apache-2.0, at your option. The GUID name table (`src/guid_names/`) is Eric Zimmerman's GuidMapping, under the MIT licence (`src/guid_names/LICENSE`). The test links and most test jump lists are Eric Zimmerman's, under the MIT licence; LnkParse3's test links and output are under the MIT licence (`tests/fixtures/lnkparse3/LICENSE`); plaso's test jump lists and `Document.doc` are under the Apache licence 2.0.
