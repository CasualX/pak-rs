use std::{fs, io, path::Path};
use crate::*;
use super::*;

/// File reader.
pub struct FileReader {
	pub(super) file: fs::File,
	pub(super) directory: Directory,
	pub(super) info: InfoHeader,
}

impl FileReader {
	/// Opens a PAK file for reading.
	///
	/// If the file at the given path is not a PAK file or the encryption key is incorrect, [`io::ErrorKind::InvalidData`] is returned.
	#[inline]
	pub fn open<P: ?Sized + AsRef<Path>>(path: &P, key: &Key) -> io::Result<FileReader> {
		open(path.as_ref(), key)
	}
}

#[inline(never)]
fn open(path: &Path, key: &Key) -> io::Result<FileReader> {
	let mut file = fs::File::open(path)?;

	let (info, directory) = read_header(&mut file, key)?;

	Ok(FileReader { file, directory, info })
}

impl ops::Deref for FileReader {
	type Target = Directory;
	#[inline]
	fn deref(&self) -> &Directory {
		&self.directory
	}
}

impl FileReader {
	/// Returns the info header.
	#[inline]
	pub fn info(&self) -> &InfoHeader {
		&self.info
	}

	/// Highest block index containing file data.
	#[inline]
	pub fn high_mark(&self) -> u32 {
		self.info.directory.offset
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
}
