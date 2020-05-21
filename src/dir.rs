/*!
Functions for manipulating the directory.

The directory is a sequence of descriptors encoding a light-weight [TLV structure](https://en.wikipedia.org/wiki/Type-length-value).

There are two types, directories and files, which share the same [`Descriptor`] struct.

* Directory descriptors have their `content_type` zero and the `content_size` encodes the number of descendants following this descriptor.

* File descriptors have their `content_type` non-zero (the interpretation of the value is left to the user) and the `content_size` specifies the size of the file in bytes.
*/

use std::{cmp, fmt, str};
use crate::*;

/// Compares if the next component of the path matches the file descriptor.
///
/// Returns None if the path does not match, otherwise returns the path with the descriptor's name removed.
///
/// # Examples
///
/// ```
/// use paks::Descriptor;
/// use paks::dir::name_eq;
///
/// // Create an empty descriptor with name "test"
/// let mut desc = Descriptor::default();
/// desc.name.set(b"test");
///
/// assert_eq!(name_eq(&desc, b"test"), Some(&b""[..]));
/// assert_eq!(name_eq(&desc, b"test/a/b"), Some(&b"a/b"[..]));
/// assert_eq!(name_eq(&desc, b"testing"), None);
/// assert_eq!(name_eq(&desc, b"te"), None);
/// ```
pub fn name_eq<'a>(desc: &Descriptor, path: &'a [u8]) -> Option<&'a [u8]> {
	let name = desc.name();
	let mut i = 0;
	loop {
		// Found the end of the name to compare to, a decision must be made
		if name.len() == i {
			// The path matched exactly
			if path.len() == i {
				break Some(&path[i..]);
			}
			// The path component matched
			if path[i] == b'/' || path[i] == b'\\' {
				break Some(&path[i + 1..]);
			}
			// The path did not match
			break None;
		}
		// Check if the name is longer than the path or name and path don't match
		if path.len() == i || name[i] != path[i] {
			break None;
		}
		// Advance
		i += 1;
	}
}

/// Calculates the next sibling index for the given descriptor.
///
/// When iterating over a directory, calculate the next sibling index for the given descriptor.
/// If it is a directory descriptor then its children will be skipped.
///
/// # Examples
///
/// Given the following directory structure:
///
/// ```text
/// +--. Foo
/// |  |   Bar
/// |  `   Baz
/// |
/// +--. Sub
/// |  `-. Dir
/// |
/// `   File
/// ```
///
/// Iterating over the top level directory:
///
/// ```
/// use paks::Descriptor;
/// use paks::dir::next_sibling;
///
/// let dir = [
/// 	// ...
/// # 	Descriptor::dir(b"Foo", 2),
/// # 	Descriptor::file(b"Bar"),
/// # 	Descriptor::file(b"Baz"),
/// # 	Descriptor::dir(b"Sub", 1),
/// # 	Descriptor::dir(b"Dir", 0),
/// # 	Descriptor::file(b"File"),
/// ];
/// # let results = [true, false, false, true, false, true];
///
/// let mut i = 0;
/// let end = dir.len();
/// while i < end {
/// 	let desc = &dir[i];
/// 	let next_i = next_sibling(desc, i, end);
///
/// 	// Process the descriptor
/// 	println!("processing dir[{}] out of {}", i, end);
/// # 	assert!(results[i]);
///
/// 	// Advance the iteration
/// 	i = next_i;
/// }
/// ```
///
/// Prints the following:
///
/// ```text
/// processing dir[0] out of 6
/// processing dir[3] out of 6
/// processing dir[5] out of 6
/// ```
///
/// # Panics
///
/// Asserts that `i < end`, which should always be the case.
/// The optimizer is be able to remove this assertion if your descriptor loop is written correctly.
#[inline]
pub fn next_sibling(desc: &Descriptor, i: usize, end: usize) -> usize {
	// After inlining the optimizer should be able to remove this
	assert!(i < end, "index out of range");
	if desc.is_dir() {
		// Gracefully handle a corrupt directory descriptor
		// Prevent overflow by clamping the next index to the original range
		let max_size = end - (i + 1);
		let min_size = cmp::min(max_size, desc.content_size as usize);
		i + 1 + min_size
	}
	else {
		i + 1
	}
}

pub fn find_desc<'a>(dir: &'a [Descriptor], path: &[u8]) -> Option<&'a Descriptor> {
	find(dir, path).get(0)
}
pub fn find_dir<'a>(dir: &'a [Descriptor], path: &[u8]) -> Option<&'a [Descriptor]> {
	if path.len() == 0 {
		Some(dir)
	}
	else {
		find(dir, path).get(1..)
	}
}

/// Traverse the directory with the given path.
///
/// Returns a slice with length zero if no descriptor was found at the given path.
///
/// Returns a slice with length one if a file descriptor was found at the given path.
///
/// Returns a slice with length larger than or equal to one if a directory descriptor was found at the given path.
/// The first entry in the slice is the directory descriptor, the tail are the child descriptors contained within the directory.
/// These children also contain any subdirectories of the returned directory.
pub fn find<'a>(dir: &'a [Descriptor], mut path: &[u8]) -> &'a [Descriptor] {
	// Reject empty paths
	if path.len() == 0 {
		return &dir[..0];
	}
	let mut i = 0;
	let mut end = dir.len();
	while i < end {
		let desc = &dir[i];
		let next_i = next_sibling(desc, i, end);
		if let Some(tail) = name_eq(desc, path) {
			// Exactly matching descriptor found
			if tail.len() == 0 {
				return &dir[i..next_i];
			}
			// Continue traversing directory descriptor
			if desc.is_dir() {
				path = tail;
				i = i + 1;
				end = next_i;
				continue;
			}
			// Found a file descriptor when expecting a director descriptor
			// Continue, maybe a directory descriptor exists with the same name
		}
		// Advance the iteration
		i = next_i;
	}
	// No descriptor with this path found
	return &dir[..0];
}

/*
/// Finds a descriptor with the given name in an encrypted directory.
///
/// The directory stays encrypted and only decrypts a single descriptor at the time.
pub fn find_encrypted(encrypted_dir: &[Descriptor], mut path: &[u8], nonce: &Block, key: &Key) -> Option<Descriptor> {
	// Reject empty paths
	if path.len() == 0 {
		return None;
	}
	let mut i = 0;
	let mut end = encrypted_dir.len();
	let mut nonce = *nonce;
	while i < end {
		let desc = crypt::decrypt_desc(&encrypted_dir[i], &nonce, key);
		let next_i = next_sibling(&desc, i, end);
		if let Some(tail) = name_eq(&desc, path) {
			// Exactly matching descriptor found
			if tail.len() == 0 {
				return Some(desc);
			}
			// Continue traversing directory descriptor
			if desc.is_dir() {
				path = tail;
				nonce = crypt::counter(&nonce, Descriptor::BLOCKS_LEN);
				i = i + 1;
				end = next_i;
				continue;
			}
			// Found a file descriptor when expecting a director descriptor
			// Continue, maybe a directory descriptor exists with the same name
		}
		// Advance the iteration
		nonce = crypt::counter(&nonce, (next_i - i) * Descriptor::BLOCKS_LEN);
		i = next_i;
	}
	// No descriptor with this path found
	return None;
}
*/

/// Art used to render the directory.
#[derive(Copy, Clone, Debug)]
pub struct Art<'a> {
	pub margin_open: &'a str,
	pub margin_closed: &'a str,
	pub dir_entry: &'a str,
	pub dir_last: &'a str,
	pub file_entry: &'a str,
	pub file_last: &'a str,
}
impl Art<'static> {
	pub const ASCII: Art<'static> = Art {
		margin_open: "   ",
		margin_closed: "|  ",
		dir_entry: "+- ",
		dir_last: "`- ",
		file_entry: "|  ",
		file_last: "`  ",
	};
	pub const UNICODE: Art<'static> = Art {
		margin_open: "   ",
		margin_closed: "│  ",
		dir_entry: "├─ ",
		dir_last: "└─ ",
		file_entry: "│  ",
		file_last: "└  ",
	};
}

pub struct Fmt<'a> {
	root: &'a str,
	dir: &'a [Descriptor],
	art: &'a Art<'static>,
}
impl<'a> Fmt<'a> {
	pub const fn new(root: &'a str, dir: &'a [Descriptor], art: &'a Art<'static>) -> Fmt<'a> {
		Fmt { root, dir, art }
	}
}
impl<'a> fmt::Display for Fmt<'a> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		// Print the root directory
		f.write_str(self.root)?;
		f.write_str(if self.root.ends_with("/") { "\n" } else { "/\n" })?;
		fmt_rec(f, 0, 0, self.dir, self.art)
	}
}

/// Formats the directory structure to a string.
///
/// # Examples
///
/// ```
/// use paks::Descriptor;
///
/// let dir = [
/// 	Descriptor::dir(b"Foo", 2),
/// 	Descriptor::file(b"Bar"),
/// 	Descriptor::file(b"Baz"),
/// 	Descriptor::dir(b"Sub", 1),
/// 	Descriptor::dir(b"Dir", 0),
/// 	Descriptor::file(b"File"),
/// ];
///
/// let expected = "\
/// ./
/// +- Foo/
/// |  |  Bar
/// |  `  Baz
/// |  
/// +- Sub/
/// |  `- Dir/
/// |  
/// `  File
/// ";
///
/// let result = paks::dir::to_string(".", &dir, &paks::dir::Art::ASCII);
/// # println!("\n{}", result);
/// assert_eq!(expected, result);
/// ```
pub fn to_string(root: &str, dir: &[Descriptor], art: &Art<'static>) -> String {
	Fmt::new(root, dir, art).to_string()
}
fn fmt_margin<W: fmt::Write>(f: &mut W, margin: u32, depth: u32, art: &Art) -> fmt::Result {
	for is_last in (0..depth).map(|i| margin & 1 << i != 0) {
		let s = if is_last { art.margin_open } else { art.margin_closed };
		f.write_str(s)?;
	}
	Ok(())
}
fn fmt_rec<W: fmt::Write>(f: &mut W, margin: u32, depth: u32, dir: &[Descriptor], art: &Art) -> fmt::Result {
	// Max supported nested directories
	if depth >= 31 {
		return Ok(());
	}

	let mut was_dir = false;
	let mut i = 0;
	while i < dir.len() {
		let desc = &dir[i];

		// Print some space between directories
		if i != 0 && (desc.is_dir() || was_dir) {
			fmt_margin(f, margin, depth + 1, art)?;
			f.write_str("\n")?;
		}
		was_dir = desc.is_dir();

		// Print the margin
		fmt_margin(f, margin, depth, art)?;

		// Calculate the next sibling descriptor index
		let next_i = next_sibling(desc, i, dir.len());

		// Write the prefix
		let is_last = dir.len() == next_i;
		let prefix = match (is_last, desc.is_dir()) {
			(true, true) => art.dir_last,
			(true, false) => art.file_last,
			(false, true) => art.dir_entry,
			(false, false) => art.file_entry,
		};
		f.write_str(prefix)?;

		// Write the filename
		match str::from_utf8(desc.name()) {
			Ok(name) => f.write_str(name),
			Err(_) => f.write_str("err"),
		}?;

		// Print directories recursively
		if desc.is_dir() {
			f.write_str("/\n")?;
			let new_margin = margin | (is_last as u32) << depth;
			fmt_rec(f, new_margin, depth + 1, &dir[i + 1..next_i], art)?;
		}
		else {
			f.write_str("\n")?;
		}

		i = next_i;
	}
	Ok(())
}

/// Increments all directory descriptors' child count along the given path.
/// Returns the index where `inc` number of descriptors must be inserted.
///
/// Does not care if a descriptor already exists and will suggest to create one with the same name.
fn dir_inc(dir: &mut Vec<Descriptor>, path: &mut &[u8], inc: i32) -> usize {
	let mut i = 0;
	let mut end = dir.len();
	while i < end {
		let desc = &mut dir[i];
		let next_i = next_sibling(desc, i, end);
		// Compare the name of this descriptor with the given path
		if let Some(tail) = name_eq(desc, *path) {
			// Found the descriptor matching this name
			if tail.len() == 0 {
				*path = tail;
				return i;
			}
			// Name matches a directory, descend
			if desc.is_dir() {
				desc.content_size = (desc.content_size as i32 + inc) as u32;
				*path = tail;
				i = i + 1;
				end = next_i;
				continue;
			}
			// Name matches a file, suggest a sibling directory with the same name
			else {
				return i;
			}
		}
		// Next descriptor
		i = next_i;
	}
	return i;
}

fn flenck(path: &[u8]) -> i32 {
	let mut components = 0;
	for i in 0..path.len() {
		if path[i] == b'/' || path[i] == b'\\' {
			if i + 1 == path.len() {
				return components;
			}
			components += 1;
		}
	}
	return components + 1;
}

/// Creates a new descriptor at the appropriate place given the path.
///
/// Non-existing sub directories are created as needed.
/// If a file exists where a directory is expected, a directory with the same name is created as the file.
pub fn create<'a>(dir: &'a mut Vec<Descriptor>, path: &[u8]) -> &'a mut Descriptor {
	// Dry run to find the index where to insert new descriptors
	let mut tail = path;
	let i = dir_inc(dir, &mut tail, 0);

	// Number of descriptors to add
	let inc = flenck(tail) as usize;

	// Adding a descriptor which already exists
	if inc == 0 {
		return &mut dir[i];
	}

	// Update the parent directories
	tail = path;
	let _check = dir_inc(dir, &mut tail, inc as i32);
	debug_assert_eq!(i, _check);

	// Splice new directory descriptors
	let mut dir_len = inc as u32;
	let _ = dir.splice(i..i, std::iter::repeat_with(|| {
		let mut k = 0;
		while k < tail.len() && tail[k] != b'/' && tail[k] != b'\\' {
			k += 1;
		}
		dir_len -= 1;
		let dir_name = &tail[..k];
		tail = &tail[if k == tail.len() { k } else { k + 1 }..];
		Descriptor::dir(dir_name, dir_len)
	}).take(inc));

	// Return the requested descriptor
	return &mut dir[i + inc - 1];
}

/// Removes a descriptor at the given path.
///
/// Returns `false` if no descriptor is found at the given path.
/// The directory remains unchanged, the output argument deleted is untouched.
///
/// Returns `true` if a file descriptor is found at the given path.
/// The descriptor is removed and optionally copied to the deleted output argument.
///
/// Returns `true` if a directory descriptor is found at the given path.
/// The descriptor is removed and optionally copied to the deleted output argument.
/// All the direct children of the removed directory are moved to its parent directory.
pub fn remove(dir: &mut Vec<Descriptor>, path: &[u8]) -> Option<Descriptor> {
	// Dry run to find the index of the descriptor to remove
	let mut temp = path;
	let i = dir_inc(dir, &mut temp, 0);

	// Early return if the descriptor wasn't found
	if i >= dir.len() {
		return None;
	}

	// Update the parent directories
	temp = path;
	let _check = dir_inc(dir, &mut temp, -1);
	debug_assert_eq!(i, _check);

	// Finally remove the descriptor
	Some(dir.remove(i))
}

pub fn fsck(dir: &[Descriptor], high_mark: u32, log: &mut dyn fmt::Write) -> bool {
	fsck_rec(dir, high_mark, None, log)
}
struct FsckParents<'a> {
	desc: &'a Descriptor,
	parents: Option<&'a FsckParents<'a>>,
}
fn fsck_rec(dir: &[Descriptor], high_mark: u32, parents: Option<&FsckParents>, log: &mut dyn fmt::Write) -> bool {
	let mut success = true;
	let mut i = 0;
	while i < dir.len() {
		let desc = &dir[i];
		i += 1;

		// Invalid name length
		if desc.name.buffer[NAME_BUF_LEN - 1] >= NAME_BUF_LEN as u8 {
			fsck_error(desc, parents, log, format_args!("invalid name length ({})", desc.name.buffer[NAME_BUF_LEN - 1]));
			success = false;
		}

		// Invalid name
		if let Err(err) = str::from_utf8(desc.name()) {
			fsck_error(desc, parents, log, format_args!("invalid name ({})", err));
			success = false;
		}

		if desc.is_file() {
			// File section overlaps the header
			if desc.section.offset < Header::BLOCKS_LEN as u32 {
				fsck_error(desc, parents, log, format_args!("invalid file section (offset={}, size={}): overlaps the header", desc.section.offset, desc.section.size));
				success = false;
			}

			// File section larger than the PAK file
			if desc.section.size > high_mark {
				fsck_error(desc, parents, log, format_args!("invalid file section (offset={}, size={}): size too large", desc.section.offset, desc.section.size));
				success = false;
			}

			// File section overlaps the directory
			if desc.section.offset > high_mark - desc.section.size {
				fsck_error(desc, parents, log, format_args!("invalid file section (offset={}, size={}): overlaps the directory", desc.section.offset, desc.section.size));
				success = false;
			}

			// File content size larger than its section size
			if bytes2blocks(desc.content_size) > desc.section.size {
				fsck_error(desc, parents, log, format_args!("invalid content size ({}, offset={}, size={}): larger than its section", desc.content_size, desc.section.offset, desc.section.size));
				success = false;
			}
		}
		else {
			// Out of bounds directory size
			let max_len = dir.len() - i;
			if desc.content_size as usize > max_len {
				fsck_error(desc, parents, log, format_args!("invalid directory: too many children ({}, max={})", desc.content_size, max_len));
				success = false;
				// Unable to recover from corrupt directory descriptor
				break;
			}

			// Recursively check the directory's children
			let children = &dir[i..i + desc.content_size as usize];
			fsck_rec(children, high_mark, Some(&FsckParents { desc, parents }), log);

			i += desc.content_size as usize;
		}
	}
	return success;
}
#[inline(never)]
fn fsck_error(desc: &Descriptor, parents: Option<&FsckParents>, log: &mut dyn fmt::Write, args: fmt::Arguments) {
	fn print_parents(parents: Option<&FsckParents>, log: &mut dyn fmt::Write) {
		if let Some(parents) = parents {
			print_parents(parents.parents, log);
			let _ = log.write_str("/");
			let _ = log.write_str(String::from_utf8_lossy(parents.desc.name()).as_ref());
		}
	}
	print_parents(Some(&FsckParents { desc, parents }), log);
	let _ = log.write_str(": ");
	let _ = log.write_fmt(args);
	let _ = log.write_str("\n");
}

//----------------------------------------------------------------

#[cfg(test)]
mod tests {
	use std::ptr;
	use super::*;

	// fn example_dir() -> Vec<Descriptor> {
	// 	vec![
	// 		Descriptor::file(b"before"),
	// 		Descriptor::dir(b"a", 3),
	// 		Descriptor::dir(b"b", 2),
	// 		Descriptor::dir(b"c", 1),
	// 		Descriptor::file(b"file"),
	// 	]
	// }

	#[test]
	fn test_find_empty() {
		assert_eq!(find(&[], b"path"), &[]);
	}

	#[test]
	fn test_find_desc01() {
		let mut dir = Vec::new();
		create(&mut dir, b"A/B/C");

		let result1 = find_desc(&dir, b"A/B/C");
		let result2 = find_desc(&dir, b"A/B/D");

		assert_eq!(result1.unwrap().name(), b"C");
		assert!(result2.is_none());
	}

	#[test]
	fn test_find() {
		let dir = [
			Descriptor::file(b"before"),
			Descriptor::dir(b"a", 3),
			Descriptor::dir(b"b", 2),
			Descriptor::dir(b"c", 1),
			Descriptor::file(b"file"),
		];

		assert!(ptr::eq(find(&dir, b"before"), &dir[0..1]));
		assert!(ptr::eq(find(&dir, b"a"), &dir[1..]));

		assert!(ptr::eq(find(&dir[2..], b"b"), &dir[2..]));

		assert_eq!(find(&dir, "file".as_ref()).len(), 0);
		assert!(ptr::eq(find(&dir[4..], b"file"), &dir[4..]));

		assert_eq!(find_desc(&dir, b"a\\b\\c\\file").map(|x| x as *const _), Some(&dir[4] as *const _));
	}

	#[test]
	fn test_create_simple() {
		let path = b"stuff.txt";

		let mut dir = Vec::new();
		create(&mut dir, path);

		assert_eq!(dir.len(), 1);
		let file = &dir[0];

		assert_eq!(file.content_type, 0);
		assert_eq!(file.content_size, 0);
		assert_eq!(file.section, Section::default());
		assert_eq!(file.name(), path);
	}

	#[test]
	fn test_create_simple_dirs() {
		let path1 = b"A/FOO";
		let path2 = b"A/BAR";

		let mut dir = Vec::new();
		create(&mut dir, path1);
		create(&mut dir, path2);

		let result = [
			Descriptor::dir(b"A", 2),
			Descriptor::dir(b"FOO", 0),
			Descriptor::dir(b"BAR", 0),
		];
		assert_eq!(dir, result);
	}

	// #[test]
	// fn test_find_encrypted() {
	// 	let mut directory = Directory::from(example_dir());
	// 	let ref key = [42, 13];
	// 	let mut section = Section {
	// 		offset: 0,
	// 		size: directory.len() as u32,
	// 		nonce: Block::default(),
	// 		mac: Block::default(),
	// 	};
	// 	crypt2::encrypt_section(directory.as_blocks_mut(), &mut section, key);
	// 	let found = find_encrypted(directory.as_ref(), b"a/b/c/file", &section.nonce, key);
	// 	assert!(matches!(found, Some(_)));
	// }
}
