PAK file
========

[![MIT License](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![crates.io](https://img.shields.io/crates/v/paks.svg)](https://crates.io/crates/paks)
[![docs.rs](https://docs.rs/paks/badge.svg)](https://docs.rs/paks)
[![Build status](https://github.com/CasualX/pak-rs/workflows/CI/badge.svg)](https://github.com/CasualX/pak-rs/actions)

The PAK file is a light-weight encrypted archive inspired by the Quake PAK format.

Command-line
------------

This project comes with an executable program `PAKtool` for creating and modifying PAK files from the command-line.

```
cargo install paks
```

The above command installs the `PAKtool` utility to manipulate PAK files.

```
PAKtool by Casper - Copyright (c) 2020-2021 Casper <CasualX@users.noreply.github.com>

USAGE
    PAKtool help <COMMAND>
    PAKtool <PAKFILE> <KEY> <COMMAND> [..]

ARGUMENTS
    PAKFILE  Path to a PAK archive to create or edit.
    KEY      The 128-bit encryption key encoded in hex.
    COMMAND  The subcommand to invoke.

Commands are:
    new      Creates a new empty PAK archive.
    tree     Displays the directory of the PAK archive.
    add      Adds a file to the PAK archive.
    copy     Copies files to the PAK archive.
    link     Links the file from alternative paths.
    cat      Reads files from the PAK archive and writes to stdout.
    rm       Removes paths from the PAK archive.
    mv       Moves files in the PAK archive.
    gc       Collects garbage left behind by removed files.

    See `PAKtool help <COMMAND>` for more information on a specific command.

EXAMPLES
    PAKtool example.pak 0 new
    PAKtool example.pak 0 add a/b/example < tests/data/example.txt
    PAKtool example.pak 0 link a/b/example aa/bb/example
    PAKtool example.pak 0 tree -u
    PAKtool example.pak 0 rm a/b/example
    PAKtool example.pak 0 cat aa/bb/example
```

Examples
--------

The following code shows how to create a new PAK file and add some content to it.

Try it out locally: `cargo run --example readme1`.

```rust
// This file contains 65 bytes filled with `0xCF`.
const DATA: &[u8] = &[0xCF; 65];

fn main() {
	let ref key = [13, 42];

	// Create the editor object to create PAK files in memory.
	let mut edit = paks::MemoryEditor::new();

	// Let's create a file `foo` under a directory `sub`.
	// If a file already exists by this name it will be overwritten.
	edit.create_file(b"sub/foo", DATA, key);

	// When done the editor object can be finalized and returns the encrypted PAK file as a `Vec<Block>`.
	// It also returns the unencrypted directory for final inspection if desired.
	let (pak, dir) = edit.finish(key);

	// Print the directory.
	print!("The directory:\n\n```\n{}```\n\n", dir.display().to_string());

	// Print the PAK file itself.
	print!("The RAW data:\n\n```\n{:x?}\n```\n", pak);

	// Create the reader object to inspect PAK files in memory.
	let read = paks::MemoryReader::from_blocks(pak, key).unwrap();

	// Find the file created earlier.
	let desc = read.find_file(b"sub/foo").unwrap();

	// Read its data into a `Vec<u8>`.
	let data = read.read_data(desc, key).unwrap();

	// Check that it still matches the expected data.
	assert_eq!(DATA, &data[..]);
}
```

File layout
-----------

The layout of the PAK file is very simple.

* The header contains a version info number and the location of the directory.

  There is no way to know whether the blob of bytes is a valid PAK file without the correct key as everything is encrypted by design.

* The data containing the file contents.

  This is an opaque blob of bytes only decodable via information in the directory.

* The directory is a sequence of descriptors encoding a light-weight [TLV structure](https://en.wikipedia.org/wiki/Type-length-value).

  File descriptors contain the location and a cryptographic nonce for accessing the file contents.
  Directory descriptors describe how many of the following descriptors are its children.

Security
--------

This library uses the [Speck cipher](https://en.wikipedia.org/wiki/Speck_\(cipher\)) in the 128/128 bit variant.

License
-------

Licensed under [MIT License](https://opensource.org/licenses/MIT), see [license.txt](license.txt).

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, shall be licensed as above, without any additional terms or conditions.
