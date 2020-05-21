use std::{fs, io, io::prelude::*, ops, path::Path};
use crate::*;
use super::*;

/// File editor.
///
/// # Consistency guarantees
///
/// The implementation makes a reasonable attempt to defend against data loss.
/// If consistency is super important then consider [`MemoryEditor`] and save a fresh copy when needed.
pub struct FileEditor {
	pub(super) file: fs::File,
	pub(super) directory: Directory,
	pub(super) high_mark: u32,
}

impl FileEditor {
	/// Creates a new PAK file, failing if it already exists.
	#[inline]
	pub fn create_new<P: ?Sized + AsRef<Path>>(path: &P, key: &Key) -> io::Result<FileEditor> {
		create_new(path.as_ref(), key)
	}

	/// Opens an existing PAK file, error if it doesn't exist.
	#[inline]
	pub fn open<P: ?Sized + AsRef<Path>>(path: &P, key: &Key) -> io::Result<FileEditor> {
		open(path.as_ref(), key)
	}

	/// Creates an empty PAK file, overwrites any file if it already exists.
	#[inline]
	pub fn create_empty<P: ?Sized + AsRef<Path>>(path: &P, key: &Key) -> io::Result<()> {
		create_empty(path.as_ref(), key)
	}

	/// Opens an existing PAK file for reading only, error if it doesn't exist.
	///
	/// Note that this method is provided because I can.
	/// See [`FileReader`] which only implements reader APIs.
	#[inline]
	pub fn read_only<P: ?Sized + AsRef<Path>>(path: &P, key: &Key) -> io::Result<FileEditor> {
		read_only(path.as_ref(), key)
	}
}

#[inline(never)]
fn create_new(path: &Path, key: &Key) -> io::Result<FileEditor> {
	let mut file = fs::OpenOptions::new().create_new(true).read(true).write(true).open(path)?;

	let mut header = Header::default();
	header.info.directory.offset = Header::BLOCKS_LEN as u32;
	header.info.directory.size = 0;
	crypt::encrypt_section(&mut [], &mut header.info.directory, key);
	crypt::encrypt_header(&mut header, key);

	// Write an empty PAK file placeholder
	file.write_all(header.as_bytes())?;
	file.sync_data()?;

	// Create the empty FileEditor
	let directory = Directory::new();
	let high_mark = Header::BLOCKS_LEN as u32;
	Ok(FileEditor { file, directory, high_mark })
}

#[inline(never)]
fn open(path: &Path, key: &Key) -> io::Result<FileEditor> {
	let mut file = fs::OpenOptions::new().read(true).write(true).open(path)?;

	let (info, directory) = read_header(&mut file, key)?;

	// Initialize the high mark right after the end of the directory
	// This ensures that in case of failure that the existing directory remains intact
	let high_mark = info.directory.offset + info.directory.size * InfoHeader::BLOCKS_LEN as u32;
	Ok(FileEditor { file, directory, high_mark })
}

#[inline(never)]
fn create_empty(path: &Path, key: &Key) -> io::Result<()> {
	let mut header = Header::default();
	header.info.directory.offset = Header::BLOCKS_LEN as u32;
	header.info.directory.size = 0;
	crypt::encrypt_section(&mut [], &mut header.info.directory, key);
	crypt::encrypt_header(&mut header, key);
	fs::write(path, header.as_bytes())
}

#[inline(never)]
fn read_only(path: &Path, key: &Key) -> io::Result<FileEditor> {
	let mut file = fs::File::open(path)?;

	let (info, directory) = read_header(&mut file, key)?;

	// Initialize the high mark right after the end of the directory
	// This ensures that in case of failure that the existing directory remains intact
	let high_mark = u32::max(Header::BLOCKS_LEN as u32, info.directory.offset + info.directory.size * InfoHeader::BLOCKS_LEN as u32);
	Ok(FileEditor { file, directory, high_mark })
}

impl ops::Deref for FileEditor {
	type Target = Directory;
	#[inline]
	fn deref(&self) -> &Directory {
		&self.directory
	}
}
impl ops::DerefMut for FileEditor {
	#[inline]
	fn deref_mut(&mut self) -> &mut Directory {
		&mut self.directory
	}
}

impl FileEditor {
	/// Highest block index containing file data.
	#[inline]
	pub fn high_mark(&self) -> u32 {
		self.high_mark
	}

	/// Creates a file descriptor at the given path.
	///
	/// Any missing parent directories are automatically created.
	#[inline]
	pub fn edit_file(&mut self, path: &[u8]) -> FileEditFile<'_> {
		let desc = self.directory.create(path);
		let file = &self.file;
		let high_mark = &mut self.high_mark;
		FileEditFile { file, desc, high_mark }
	}

	/// Creates a file at the given path.
	///
	/// The file is assigned a content_type of `1`.
	/// A new section is allocated and the data is encrypted and written into the section.
	///
	/// Any missing parent directories are automatically created.
	///
	/// If the data's len is greater than 4 GiB it is truncated as its size is stored in a `u32`.
	pub fn create_file(&mut self, path: &[u8], data: &[u8], key: &Key) -> io::Result<&Descriptor> {
		let mut edit_file = self.edit_file(path);
		edit_file.set_content(1, data.len() as u32);
		edit_file.allocate_data().write_data(data, key)?;
		Ok(edit_file.desc)
	}

	/// Decrypts the section.
	///
	/// The key is not required to be the same as used to open the PAK file.
	///
	/// # Errors
	///
	/// * [`io::ErrorKind::InvalidInput`]: The the descriptor is not a file descriptor.
	/// * [`io::ErrorKind::InvalidData`]: The file's MAC is incorrect, the file is corrupted.
	/// * [`io::Error`]: An error encountered reading the underlying PAK file.
	#[inline]
	pub fn read_section(&self, section: &Section, key: &Key) -> io::Result<Vec<Block>> {
		read_section(&self.file, section, key)
	}

	/// Decrypts the contents of the given file descriptor.
	///
	/// See [`read_section`](Self::read_section) for more information.
	pub fn read_data(&self, desc: &Descriptor, key: &Key) -> io::Result<Vec<u8>> {
		if !desc.is_file() {
			Err(io::ErrorKind::InvalidInput)?;
		}

		let blocks = read_section(&self.file, &desc.section, key)?;

		// Figure out which part of the blocks to copy
		let data = blocks.as_bytes();
		let len = usize::min(data.len(), desc.content_size as usize);
		Ok(data[..len].to_vec())
	}

	/// Decrypts the contents of the given file descriptor into the dest buffer.
	///
	/// See [`read_section`](Self::read_section) for more information.
	pub fn read_into(&self, desc: &Descriptor, key: &Key, byte_offset: usize, dest: &mut [u8]) -> io::Result<()> {
		if !desc.is_file() {
			Err(io::ErrorKind::InvalidInput)?;
		}

		let blocks = read_section(&self.file, &desc.section, key)?;

		// Figure out which part of the blocks to copy
		let data = match blocks.as_bytes().get(byte_offset..byte_offset + dest.len()) {
			Some(data) => data,
			None => Err(io::ErrorKind::InvalidInput)?,
		};

		// Copy the data to its destination
		dest.copy_from_slice(data);

		Ok(())
	}

	/// Finish editing the PAK file.
	///
	/// Encrypts and appends the directory to the PAK file.
	/// Before updating the new header the file is synced to attempt to preserve consistency.
	/// Finally the header is updated to point to the new directory.
	///
	/// Dropping the PAK file without calling `finish` results in any changes being lost.
	pub fn finish(self, key: &Key) -> io::Result<()> {
		let FileEditor { mut file, mut directory, high_mark } = self;

		let mut header = Header {
			nonce: Block::default(),
			mac: Block::default(),
			info: InfoHeader {
				version: InfoHeader::VERSION,
				_unused: 0,
				directory: Section {
					offset: high_mark,
					size: directory.len() as u32,
					nonce: Block::default(),
					mac: Block::default(),
				},
			},
		};

		// Encrypt the directory
		crypt::encrypt_section(directory.as_blocks_mut(), &mut header.info.directory, key);

		// Encrypt the header
		let mut section = Header::SECTION;
		crypt::encrypt_section(header.info.as_mut(), &mut section, key);

		header.nonce = section.nonce;
		header.mac = section.mac;

		// Append the directory
		let dir_offset = high_mark as u64 * BLOCK_SIZE as u64;
		file.seek(io::SeekFrom::Start(dir_offset))?;
		file.write_all(directory.as_ref().as_bytes())?;

		// IMPORTANT! In order to prevent corruption:
		// Ensure that the above write of the directory is synced
		// If this isn't done then overwriting the header may result in data loss
		file.sync_data()?;

		// Finally write the new header
		// It is assumed that this write is atomic as it's pretty small and at the start of the file
		file.seek(io::SeekFrom::Start(0))?;
		file.write_all(header.as_bytes())?;

		Ok(())
	}
}
