/*!
Implements PAKtool's command-line interface.
*/

#![allow(non_snake_case)]

use std::{env, fs, io, io::prelude::*, path, str};
use dataview::Pod;

fn main() {
	let args: Vec<_> = env::args().collect();
	let args: Vec<_> = args.iter().map(|s| &**s).collect();

	match &args[1..] {
		&[] => print!("{}", HELP_GENERAL),
		&["help"] => print!("{}", HELP_GENERAL),
		&[_] => eprintln!("Error invalid syntax, see `PAKtool help`."),
		&["help", cmd] => help(&[cmd]),
		&[_, _] => eprintln!("Error invalid syntax, see `PAKtool help`."),
		&[_pak, _key, "help", ref args @ ..] => help(args),
		&[pak, key, "new", ref args @ ..] => new(pak, key, args),
		&[pak, key, "tree", ref args @ ..] => tree(pak, key, args),
		&[pak, key, "add", ref args @ ..] => add(pak, key, args),
		&[pak, key, "copy", ref args @ ..] => copy(pak, key, args),
		&[pak, key, "link", ref args @ ..] => link(pak, key, args),
		&[pak, key, "cat", ref args @ ..] => cat(pak, key, args),
		&[pak, key, "rm", ref args @ ..] => rm(pak, key, args),
		&[pak, key, "mv", ref args @ ..] => mv(pak, key, args),
		&[pak, key, "fsck", ref args @ ..] => fsck(pak, key, args),
		&[pak, key, "gc", ref args @ ..] => gc(pak, key, args),
		&[pak, key, "dbg", ref args @ ..] => dbg(pak, key, args),
		&[_pak, _key, cmd, ..] => eprintln!("Error unknown subcommand: {}", cmd),
	}
}

fn parse_key(s: &str) -> Option<paks::Key> {
	match u128::from_str_radix(s, 16) {
		Ok(val) => {
			Some([(val & 0xffffffffffffffff) as u64, (val >> 64) as u64])
		},
		Err(err) => {
			eprintln!("Error parsing key argument: {}", err);
			None
		},
	}
}

//----------------------------------------------------------------

const HELP_GENERAL: &str = "\
PAKtool - Copyright (c) 2020-2021 Casper <CasualX@users.noreply.github.com>

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
    fsck     File system consistency check.
    gc       Collects garbage left behind by removed files.

    See `PAKtool help <COMMAND>` for more information on a specific command.

EXAMPLES
    PAKtool example.pak 0 new
    PAKtool example.pak 0 add a/b/example < tests/data/example.txt
    PAKtool example.pak 0 link a/b/example aa/bb/example
    PAKtool example.pak 0 tree -u
    PAKtool example.pak 0 rm a/b/example
    PAKtool example.pak 0 cat aa/bb/example
";

fn help(args: &[&str]) {
	let text = match args.first().cloned() {
		None => HELP_GENERAL,
		Some("new") => HELP_NEW,
		Some("tree") => HELP_TREE,
		Some("add") => HELP_ADD,
		Some("copy") => HELP_COPY,
		Some("link") => HELP_LINK,
		Some("cat") => HELP_CAT,
		Some("rm") => HELP_RM,
		Some("mv") => HELP_MV,
		Some("fsck") => HELP_FSCK,
		Some("gc") => HELP_GC,
		Some(cmd) => return eprintln!("Error unknown subcommand: {}", cmd),
	};
	print!("{}", text);
}

//----------------------------------------------------------------

const HELP_NEW: &str = "\
PAKtool new

NAME
    PAKtool-new - Creates a new empty PAK archive.

DESCRIPTION
    Creates a new empty PAK archive with the given file name and encryption key.
    If a file with this name already exists it will be overwritten.
";

fn new(file: &str, key: &str, _args: &[&str]) {
	let ref key = match parse_key(key) {
		Some(key) => key,
		None => return,
	};

	if let Err(err) = paks::FileEditor::create_empty(file, key) {
		eprintln!("Error writing {}: {}", file, err);
	}
}

//----------------------------------------------------------------

const HELP_TREE: &str = "\
PAKtool tree

NAME
    PAKtool-tree - Displays the directory of the PAK archive.

SYNOPSIS
    PAKtool [..] tree [-au] [PATH]

DESCRIPTION
    Displays the directory of the PAK archive.

ARGUMENTS
    -a       Display using ASCII art.
    -u       Display using UNICODE art.
    PATH     Optional subdirectory to start at.
";

fn tree(file: &str, key: &str, mut args: &[&str]) {
	let ref key = match parse_key(key) {
		Some(key) => key,
		None => return,
	};

	let mut art = &paks::dir::Art::UNICODE;
	while let Some(head) = args.first().cloned() {
		if head.starts_with("-") {
			args = &args[1..];
			match head {
				"-a" => art = &paks::dir::Art::ASCII,
				"-u" => art = &paks::dir::Art::UNICODE,
				_ => eprintln!("Unknown argument: {}", head),
			}
		}
		else {
			break;
		}
	}

	let path = match args {
		&[path] => Some(path),
		[..] => None,
	};

	let reader = match paks::FileReader::open(file, key) {
		Ok(reader) => reader,
		Err(err) => return eprintln!("Error opening {}: {}", file, err),
	};

	let dir = match reader.get_children(path.unwrap_or("").as_bytes()) {
		Some(path) => path,
		None => return eprintln!("Error directory not found or is a file: {}", path.unwrap_or("")),
	};

	let root = path.unwrap_or(".");
	println!("{}", paks::dir::Fmt::new(root, dir, art));
}

//----------------------------------------------------------------

const HELP_ADD: &str = "\
PAKtool add

NAME
    PAKtool-add - Adds a file to the PAK archive.

SYNOPSIS
    PAKtool [..] add <PATH> < <CONTENT>

DESCRIPTION
    Adds a file to the PAK archive.

ARGUMENTS
    PATH     The destination path in the PAK archive to put the file.
    CONTENT  The file data to write in the PAK archive passed via stdin.
";

fn add(file: &str, key: &str, args: &[&str]) {
	let ref key = match parse_key(key) {
		Some(key) => key,
		None => return,
	};

	let path = match args {
		[path] => path,
		_ => return eprintln!("Error invalid path: expected exactly 1 argument."),
	};

	let mut data = Vec::new();
	match io::stdin().read_to_end(&mut data) {
		Ok(_) => (),
		Err(err) => return eprintln!("Error reading stdin: {}", err),
	};

	let mut edit = match paks::FileEditor::open(file, key) {
		Ok(edit) => edit,
		Err(err) => return eprintln!("Error opening {}: {}", file, err),
	};

	if let Err(err) = edit.create_file(path.as_bytes(), &data, key) {
		eprintln!("Error creating {}: {}", path, err);
	}

	if let Err(err) = edit.finish(key) {
		eprintln!("Error writing {}: {}", file, err);
	}
}

//----------------------------------------------------------------

const HELP_COPY: &str = "\
PAKtool copy

NAME
    PAKtool-copy - Copies files to the PAK archive.

SYNOPSIS
    PAKtool [..] copy <PATH> [FILE]..

DESCRIPTION
    Copies files to the PAK archive.
";

fn copy(file: &str, key: &str, args: &[&str]) {
	let ref key = match parse_key(key) {
		Some(key) => key,
		None => return,
	};

	if args.len() < 1 {
		return eprintln!("Error invalid syntax: expecting one path followed by many filenames.");
	}
	else if args.len() == 1 {
		return;
	}
	let base_path = args[0];

	let mut edit = match paks::FileEditor::open(file, key) {
		Ok(edit) => edit,
		Err(err) => return eprintln!("Error opening {}: {}", file, err),
	};

	let mut dest_path = String::from(base_path);
	if !dest_path.ends_with("/") {
		dest_path.push_str("/");
	}
	let dest_len = dest_path.len();

	for src_path in &args[1..] {
		let src_path = path::Path::new(src_path);

		// Read the file contents
		let data = match fs::read(src_path) {
			Ok(data) => data,
			Err(err) => {
				eprintln!("Error reading {}: {}", src_path.display(), err);
				continue;
			},
		};

		// Extract the file name
		let file_name = match src_path.file_name().and_then(|s| s.to_str()) {
			Some(file_name) => file_name,
			None => {
				eprintln!("Error invalid file name: {}", src_path.display());
				continue;
			},
		};

		// Construct destination path
		dest_path.truncate(dest_len);
		dest_path.push_str(file_name);

		// Write its contents to the PAK archive
		if let Err(err) = edit.create_file(dest_path.as_bytes(), &data, key) {
			eprintln!("Error creating {}: {}", dest_path, err);
		}
	}

	if let Err(err) = edit.finish(key) {
		eprintln!("Error writing {}: {}", file, err);
	}
}

//----------------------------------------------------------------

const HELP_LINK: &str = "\
PAKtool link

NAME
    PAKtool-link - Links the file from alternative paths.

SYNOPSIS
    PAKtool [..] link <SRC> [DEST]..

DESCRIPTION
    Links the source file to alternative destination paths.
    Returns file not found error if the SRC path does not exist.

ARGUMENTS
    SRC      Path to the source file to link.
    DEST     One or more destination paths where to link the SRC.
";

fn link(file: &str, key: &str, args: &[&str]) {
	let ref key = match parse_key(key) {
		Some(key) => key,
		None => return,
	};

	let (src_path, dest_paths) = match args {
		&[src, ref dest @ ..] => (src, dest),
		_ => return eprintln!("Error invalid syntax: expecting a source file"),
	};

	let mut edit = match paks::FileEditor::open(file, key) {
		Ok(edit) => edit,
		Err(err) => return eprintln!("Error opening {}: {}", file, err),
	};

	let src_desc = match edit.find_desc(src_path.as_bytes()) {
		Some(desc) if desc.is_dir() => return eprintln!("Error file not found: {}", src_path),
		Some(desc) => *desc,
		None => return eprintln!("Error file not found: {}", src_path),
	};

	for &dest_path in dest_paths {
		edit.create_link(dest_path.as_bytes(), &src_desc);
	}

	if let Err(err) = edit.finish(key) {
		eprintln!("Error writing {}: {}", file, err);
	}
}

//----------------------------------------------------------------

const HELP_CAT: &str = "\
PAKtool cat

NAME
    PAKtool-cat - Reads files from the PAK archive and writes to stdout.

SYNOPSIS
    PAKtool [..] cat [PATH]..

DESCRIPTION
    Reads files from the PAK archive and writes to stdout.
    Each file is read in the order specified and written to stdout one after another.
    If an error happens it is printed and continues to write the rest of the files.

ARGUMENTS
    PATH     Path to the file in the PAK archive to output.
";

fn cat(file: &str, key: &str, args: &[&str]) {
	let ref key = match parse_key(key) {
		Some(key) => key,
		None => return,
	};

	let reader = match paks::FileReader::open(file, key) {
		Ok(reader) => reader,
		Err(err) => return eprintln!("Error opening {}: {}", file, err),
	};

	for &path in args {
		match reader.find_file(path.as_bytes()) {
			Some(file_desc) => {
				match reader.read_data(&file_desc, key) {
					Ok(data) => {
						if let Err(err) = io::stdout().write_all(&data) {
							eprintln!("Error writing {} to stdout: {}", path, err);
						}
					},
					Err(err) => eprintln!("Error reading {}: {}", path, err),
				}
			},
			None => eprintln!("Error file not found: {}", path),
		}
	}
}

//----------------------------------------------------------------

const HELP_RM: &str = "\
PAKtool rm

NAME
    PAKtool-rm - Removes files from the PAK archive.

SYNOPSIS
    PAKtool [..] rm [PATH]..

DESCRIPTION
    Removes files from the PAK archive.

ARGUMENTS
    PATH     Path to the file in the PAK archive to remove.
";

fn rm(file: &str, key: &str, args: &[&str]) {
	let ref key = match parse_key(key) {
		Some(key) => key,
		None => return,
	};

	let mut edit = match paks::FileEditor::open(file, key) {
		Ok(edit) => edit,
		Err(err) => return eprintln!("Error opening {}: {}", file, err),
	};

	for &path in args {
		if edit.remove(path.as_bytes()).is_none() {
			eprintln!("Unable to remove {}: file not found?", path);
		}
	}

	if let Err(err) = edit.finish(key) {
		eprintln!("Error writing {}: {}", file, err);
	}
}

//----------------------------------------------------------------

const HELP_MV: &str = "\
PAKtool mv

NAME
    PAKtool-mv - Moves files in the PAK archive.

SYNOPSIS
    PAKtool [..] mv <SRC> <DEST>

DESCRIPTION
    Moves files in the PAK archive.

ARGUMENTS
    SRC      Path to the source file.
    DEST     Path to the destination file.
";

fn mv(file: &str, key: &str, args: &[&str]) {
	let ref key = match parse_key(key) {
		Some(key) => key,
		None => return,
	};

	let (src_path, dest_path) = match args {
		&[src_path, dest_path] => (src_path, dest_path),
		[..] => return eprintln!("Error invalid syntax: expecting exactly two path arguments."),
	};

	let mut edit = match paks::FileEditor::open(file, key) {
		Ok(edit) => edit,
		Err(err) => return eprintln!("Error opening {}: {}", file, err),
	};

	edit.move_file(src_path.as_bytes(), dest_path.as_bytes());

	if let Err(err) = edit.finish(key) {
		eprintln!("Error writing {}: {}", file, err);
	}
}

//----------------------------------------------------------------

const HELP_FSCK: &str = "\
PAKtool fsck

NAME
    PAKtool-fsck - File system consistency check.

SYNOPSIS
    PAKtool [..] fsck

DESCRIPTION
    Checks the PAK file's directory for errors.
";

fn fsck(file: &str, key: &str, _args: &[&str]) {
	let ref key = match parse_key(key) {
		Some(key) => key,
		None => return,
	};

	let reader = match paks::FileReader::open(file, key) {
		Ok(reader) => reader,
		Err(err) => return eprintln!("Error opening {}: {}", file, err),
	};

	let mut log = String::new();
	let msg = if !reader.fsck(reader.high_mark(), &mut log) {
		"PAK file contains errors:\n"
	}
	else {
		"No errors found!\n"
	};

	print!("{}{}", msg, log);
}

//----------------------------------------------------------------

const HELP_GC: &str = "\
PAKtool gc

NAME
    PAKtool-gc - Collects garbage left behind by removed files.

SYNOPSIS
    PAKtool [..] gc

DESCRIPTION
    Collects garbage left behind by removed files.
    When files are removed their data is left behind.
    These files are unreadable because their cryptographic nonce is forgotten.
";

fn gc(file: &str, key: &str, _args: &[&str]) {
	let ref key = match parse_key(key) {
		Some(key) => key,
		None => return,
	};

	let f = match fs::File::open(file) {
		Ok(f) => f,
		Err(err) => return eprintln!("Error opening {}: {}", file, err),
	};

	let blocks = match paks::read(f, key) {
		Ok(blocks) => blocks,
		Err(err) => return eprintln!("Error reading {}: {}", file, err),
	};

	let mut edit = match paks::MemoryEditor::from_blocks(blocks, key) {
		Ok(edit) => edit,
		Err(_) => return eprintln!("Error invalid {}: not a PAK file", file),
	};

	edit.gc();

	let (data, _) = edit.finish(key);
	if let Err(err) = fs::write(file, data.as_bytes()) {
		eprintln!("Error writing {}: {}", file, err);
	}
}

//----------------------------------------------------------------

fn dbg(file: &str, key: &str, _args: &[&str]) {
	let ref key = match parse_key(key) {
		Some(key) => key,
		None => return,
	};

	let reader = match paks::FileReader::open(file, key) {
		Ok(reader) => reader,
		Err(err) => return eprintln!("Error opening {}: {}", file, err),
	};

	print!("{:#?}", reader.as_ref());
}
