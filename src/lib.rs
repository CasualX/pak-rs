/*!
PAK file
========

The PAK file format is a light-weight encrypted archive inspired by the Quake PAK format.

File Format
-----------

The file format starts with a [`Header`] which contains the cryptographic nonce and mac to decrypt the [`InfoHeader`] contained in the header.

The smallest addressable unit of the file format is a [`Block`], the entire file format can be read into an array of these Blocks.

Addresses and sizes as referenced by [`Section`] objects, their 32-bit address and length fields reference blocks, not byte offsets.
This limits the file format to a maximum of 64 GiB, individual files are limited to a maximum 4 GiB each.

The [`InfoHeader`] contains a section object referencing the [`Directory`].

The directory encodes a file hierarchy in a light-weight [TLV structure](https://en.wikipedia.org/wiki/Type-length-value).
The file format expects the directory to come at the end of the PAK file.

The individual files' data are stored in between the header and the directory in no particular order.
When files are removed their data isn't immediately reclaimed leaving behind gaps.
An explicit garbage collection can rewrite the PAK file to reclaim this unused space.

The encryption SPECK128/128 and authentication CBC-MAC are not optional or configurable.
These operations are performed on a per-file basis, the whole PAK file does not need to be checked beforehand.

Getting started
---------------

PAK files can be inspected with the standard file IO with [`FileReader`] and [`FileEditor`], or from memory with [`MemoryReader`] and [`MemoryEditor`].

### Creating PAK files

Using a [`MemoryEditor`] instance:

```
// Create a new memory editor and choose your encryption keys
let ref key = paks::Key::default();
let mut editor = paks::MemoryEditor::new();

// Add content to the PAK file
editor.create_file(b"foo/example", include_bytes!("../tests/data/example.txt"), key);

// Finish the PAK file and write to disk
let (blocks, _) = editor.finish(key);
# /* Don't actually write the file while running tests...
std::fs::write("myfile.pak", paks::as_bytes(&blocks)).unwrap();
# */
```

Using a [`FileEditor`] instance:

```no_run
# // Don't actually write files while running tests...
// Create a new file editor and choose your encryption keys
let ref key = paks::Key::default();
let mut editor = paks::FileEditor::create_new("myfile.pak", key).unwrap();

// Add content to the PAK file
editor.create_file(b"foo/example", include_bytes!("../tests/data/example.txt"), key);

// Finish writing the PAK file
editor.finish(key).unwrap();

// If the editor is dropped without calling finish
// any changes since creating the editor are lost
```

Consider using the `PAKtool` command-line application for bundling your assets separately.

### Reading PAK files

Using a [`FileReader`] instance:

```no_run
# // The test file doesn't exist...
// Construct the key and simply open the file
let ref key = paks::Key::default();
let reader = paks::FileReader::open("myfile.pak", key).unwrap();

// Lookup the file descriptor and read its data
let desc = reader.find_file(b"foo/example").expect("file not found");
let data = reader.read_data(desc, key).unwrap();

// If the PAK file was tampered with without knowing the key,
// reading the file will fail with an error
```
*/

use std::{fmt, mem, ops, str};
use dataview::Pod;

// Must be a macro, inline function does not work
// #[cfg(debug_assertions)]
// macro_rules! unsafe_assume {
// 	($cond:expr) => {
// 		assert!($cond);
// 	};
// }
// #[cfg(not(debug_assertions))]
// macro_rules! unsafe_assume {
// 	($cond:expr) => {
// 		if !$cond {
// 			unsafe { std::hint::unreachable_unchecked() }
// 		}
// 	};
// }

mod cipher;
mod crypt;

// The API exposed by the directory module is unstable but has to be public for paktool and friends
#[doc(hidden)]
pub mod dir;

mod directory;
pub use self::directory::*;

// mod memory_reader;
// mod memory_editor;
// pub use self::memory_reader::MemoryReader;
// pub use self::memory_editor::{MemoryEditor, MemoryEditFile};

mod file_io;
pub use self::file_io::*;

mod memory;
pub use self::memory::*;

/// Block primitive.
///
/// A block is the smallest addressable unit of which the PAK file is made.
/// It defines the size and alignment of the underlying storage.
pub type Block = [u64; 2];

/// Key type.
///
/// All PAK files are encrypted with the 128-bit Speck cipher.
pub type Key = [u64; 2];

const BLOCK_SIZE: usize = mem::size_of::<Block>();
// const KEY_SIZE: usize = mem::size_of::<Key>();

/// Section object.
///
/// A section object defines a location in the PAK file and its cryptographic nonce and MAC.
#[derive(Copy, Clone, Default, Eq, PartialEq, Hash)]
#[repr(C)]
pub struct Section {
	/// Offset in blocks to the start of the section.
	pub offset: u32,
	/// Length in blocks of the section.
	pub size: u32,
	/// Cryptographic nonce used for this section.
	pub nonce: Block,
	/// Cryptographic MAC used to authenticate this section.
	pub mac: Block,
}

impl Section {
	fn range_usize(&self) -> ops::Range<usize> {
		self.offset as usize..(self.offset.wrapping_add(self.size)) as usize
	}
}

impl fmt::Debug for Section {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.debug_struct("Section")
			.field("offset", &self.offset)
			.field("size", &self.size)
			.field("nonce", &format_args!("[{:#x}, {:#x}]", self.nonce[0], self.nonce[1]))
			.field("mac", &format_args!("[{:#x}, {:#x}]", self.mac[0], self.mac[1]))
			.finish()
	}
}

unsafe impl Pod for Section {}

fn bytes2blocks(byte_size: u32) -> u32 {
	if byte_size == 0 { 0 } else { (byte_size - 1) / BLOCK_SIZE as u32 + 1 }
}

//----------------------------------------------------------------

/// The info header.
#[derive(Copy, Clone, Default, Eq, PartialEq, Hash)]
#[repr(C)]
pub struct InfoHeader {
	/// Version info value, should be equal to [`VERSION`](Self::VERSION).
	pub version: u32,
	pub _unused: u32,
	/// The section object describing the location of the directory.
	///
	/// Special note: the section size specifies the number of `Descriptors` not the number of blocks.
	pub directory: Section,
}

impl InfoHeader {
	/// File format version number.
	///
	/// Note that this PAK library is endian sensitive.
	/// When inspecting PAK files on a machine with incorrect endianness the version check will fail.
	pub const VERSION: u32 = u32::from_ne_bytes(*b"PAK1");
}

impl fmt::Debug for InfoHeader {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.debug_struct("InfoHeader")
			.field("version", &self.version)
			.field("directory", &self.directory)
			.finish()
	}
}

/// The file header.
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Hash)]
#[repr(C)]
pub struct Header {
	/// Cryptographic nonce used for the info header.
	pub nonce: Block,
	/// Cryptographic MAC used to authenticate the info header.
	pub mac: Block,
	/// Version information and directory section.
	pub info: InfoHeader,
}

impl Header {
	pub(crate) const SECTION: Section = Section {
		offset: Header::BLOCKS_LEN as u32 - InfoHeader::BLOCKS_LEN as u32,
		size: InfoHeader::BLOCKS_LEN as u32,
		nonce: [0, 0],
		mac: [0, 0],
	};
}

//----------------------------------------------------------------

/// The file or directory descriptor.
#[derive(Copy, Clone, Default, Eq, PartialEq, Hash)]
#[repr(C)]
pub struct Descriptor {
	/// The content type of the descriptor.
	///
	/// If the content type is zero this is a directory descriptor, otherwise it is a file descriptor.
	/// The interpretation of a non-zero content type is left to the user of the API.
	pub content_type: u32,
	/// The content size of the descriptor.
	///
	/// Directory descriptors define it as the number of children contained in the directory.
	/// File descriptors define it as the size of the file in bytes.
	pub content_size: u32,
	/// The section object.
	///
	/// File descriptors use it to find and decrypt its contents.
	/// It is unused for directory descriptors.
	pub section: Section,
	/// The name of the descriptor, see [`name`](Self::name).
	pub name: Name,
	/// Extra meta section object, unused for now.
	pub meta: Section,
}

impl Descriptor {
	/// Creates a new empty descriptor with the given name, content type and size.
	///
	/// The descriptor is a directory descriptor if its `content_type` is zero.
	/// Its `content_size` specifies the number of children contained in the directory.
	///
	/// The descriptor is a file descriptor if its `content_type` is non-zero.
	/// The interpretation of this non-zero type is left to the user of the API.
	/// Its `content_size` specifies the size of the file in bytes.
	pub fn new(name: &[u8], content_type: u32, content_size: u32) -> Descriptor {
		Descriptor {
			content_type,
			content_size,
			name: Name::from(name),
			..Descriptor::default()
		}
	}

	/// Creates an empty file descriptor.
	pub fn file(name: &[u8]) -> Descriptor {
		Descriptor::new(name, 1, 0)
	}

	/// Creates a directory descriptor and given the number of children.
	pub fn dir(name: &[u8], len: u32) -> Descriptor {
		Descriptor::new(name, 0, len)
	}

	/// Gets the descriptor's file name.
	pub fn name(&self) -> &[u8] {
		self.name.get()
	}

	/// Is this a directory descriptor?
	pub fn is_dir(&self) -> bool {
		self.content_type == 0
	}

	/// Is this a file descriptor?
	pub fn is_file(&self) -> bool {
		self.content_type != 0
	}
}

impl fmt::Debug for Descriptor {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.debug_struct("Descriptor")
			.field("name", &self.name)
			.field("content_type", &self.content_type)
			.field("content_size", &self.content_size)
			.field("section", &self.section)
			.finish()
	}
}

//----------------------------------------------------------------

const NAME_BUF_LEN: usize = 40;

/// The descriptor name buffer.
///
/// The length of the name is stored in the last byte of the buffer.
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct Name {
	pub buffer: [u8; NAME_BUF_LEN],
}

impl Default for Name {
	#[inline]
	fn default() -> Name {
		Name {
			buffer: [0u8; NAME_BUF_LEN]
		}
	}
}

impl Name {
	/// Gets the file name.
	#[inline]
	pub fn get(&self) -> &[u8] {
		let len = usize::min(self.buffer[NAME_BUF_LEN - 1] as usize, NAME_BUF_LEN - 1);
		&self.buffer[..len]
	}

	/// Sets the file name.
	///
	/// File names longer than the internal buffer's length are cut off.
	#[inline]
	pub fn set(&mut self, name: &[u8]) {
		self.buffer = [0u8; NAME_BUF_LEN];
		let len = usize::min(name.len(), NAME_BUF_LEN - 1);
		self.buffer[NAME_BUF_LEN - 1] = len as u8;
		self.buffer[..len].copy_from_slice(&name[..len]);
	}
}

impl<'a> From<&'a [u8]> for Name {
	#[inline]
	fn from(name: &'a [u8]) -> Name {
		let mut x = Name::default();
		x.set(name);
		return x;
	}
}

impl fmt::Debug for Name {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		str::from_utf8(self.get()).unwrap_or("ERR").fmt(f)
	}
}

//----------------------------------------------------------------

macro_rules! impl_blocks {
	($ty:ty) => {
		// Error if sizeof $ty is not a multiple of BLOCK_SIZE
		const _: [(); 0] = [(); mem::size_of::<$ty>() % BLOCK_SIZE];

		unsafe impl Pod for $ty {}

		impl $ty {
			const BLOCKS_LEN: usize = mem::size_of::<$ty>() / BLOCK_SIZE;
		}

		impl AsRef<[Block; Self::BLOCKS_LEN]> for $ty {
			fn as_ref(&self) -> &[Block; Self::BLOCKS_LEN] {
				unsafe { &*(self as *const _ as *const _) }
			}
		}
		impl AsRef<$ty> for [Block; <$ty>::BLOCKS_LEN] {
			fn as_ref(&self) -> &$ty {
				unsafe { &*(self as *const _ as *const _) }
			}
		}
		impl AsMut<[Block; Self::BLOCKS_LEN]> for $ty {
			fn as_mut(&mut self) -> &mut [Block; Self::BLOCKS_LEN] {
				unsafe { &mut *(self as *mut _ as *mut _) }
			}
		}
		impl AsMut<$ty> for [Block; <$ty>::BLOCKS_LEN] {
			fn as_mut(&mut self) -> &mut $ty {
				unsafe { &mut *(self as *mut _ as *mut _) }
			}
		}
		impl From<[Block; Self::BLOCKS_LEN]> for $ty {
			fn from(blocks: [Block; Self::BLOCKS_LEN]) -> $ty {
				unsafe { mem::transmute(blocks) }
			}
		}
		impl From<$ty> for [Block; <$ty>::BLOCKS_LEN] {
			fn from(header: $ty) -> [Block; <$ty>::BLOCKS_LEN] {
				unsafe { mem::transmute(header) }
			}
		}
	};
}

impl_blocks!(Header);
impl_blocks!(InfoHeader);
impl_blocks!(Descriptor);

#[test]
fn test_print_sizes() {
	fn print_size<T>(name: &str) {
		println!("sizeof={:#x} (struct {})", std::mem::size_of::<T>(), name);
	}
	print_size::<Header>("Header");
	print_size::<InfoHeader>("InfoHeader");
	print_size::<Descriptor>("Descriptor");
	print_size::<Section>("Section");
	print_size::<Name>("Name");
}
