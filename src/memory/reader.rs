use std::ops;
use crate::*;
use super::*;

/// Memory reader.
///
/// This implementation keeps the entire PAK file in memory.
pub struct MemoryReader {
	blocks: Vec<Block>,
	directory: Directory,
}

impl MemoryReader {
	/// Parses the bytes as the PAK file format for reading.
	///
	/// # Notes
	///
	/// The reader has specific alignment requirements for the buffer.
	/// For this reason the entire byte array will be copied to an internal buffer.
	///
	/// # Errors
	///
	/// * [`ErrorKind::InvalidInput`]: Bytes length is not a multiple of the block size.
	/// * [`ErrorKind::InvalidData`]: Incorrect version info or authentication checks failed.
	pub fn from_bytes(bytes: &[u8], key: &Key) -> Result<MemoryReader, ErrorKind> {
		// The input bytes must be a multiple of the BLOCK_SIZE or this is nonsense
		if bytes.len() % BLOCK_SIZE != 0 {
			return Err(ErrorKind::InvalidInput);
		}

		// Allocate enough space to hold the blocks equivalent
		// This is necessary as internal operations have alignment requirements
		// Copy the input into these blocks
		let mut blocks = vec![Block::default(); bytes.len() / BLOCK_SIZE];
		blocks.as_bytes_mut()[..bytes.len()].copy_from_slice(bytes);

		match from_blocks(blocks, key) {
			Ok((blocks, directory)) => Ok(MemoryReader { blocks, directory }),
			Err(_) => return Err(ErrorKind::InvalidData),
		}
	}

	/// Parses the blocks as the PAK file format for reading.
	pub fn from_blocks(blocks: Vec<Block>, key: &Key) -> Result<MemoryReader, Vec<Block>> {
		from_blocks(blocks, key).map(|(blocks, directory)| MemoryReader { blocks, directory })
	}
}

impl ops::Deref for MemoryReader {
	type Target = Directory;
	#[inline]
	fn deref(&self) -> &Directory {
		&self.directory
	}
}

impl MemoryReader {
	/// Decrypts and authenticates the section.
	///
	/// The key is not required to be the same as used to open the PAK file.
	#[inline]
	pub fn read_section(&self, section: &Section, key: &Key) -> Result<Vec<Block>, ErrorKind> {
		read_section(&self.blocks, section, key)
	}

	/// Decrypts the contents of the given file descriptor.
	///
	/// The key is not required to be the same as used to open the PAK file.
	///
	/// # Notes
	///
	/// Every call decrypts and authenticates the entire section. If performance is important,
	/// consider [`read_section`](Self::read_section) and manually extract the data.
	pub fn read_data(&self, desc: &Descriptor, key: &Key) -> Result<Vec<u8>, ErrorKind> {
		if !desc.is_file() {
			return Err(ErrorKind::InvalidInput);
		}

		let blocks = read_section(&self.blocks, &desc.section, key)?;

		// Figure out which part of the blocks to copy
		let data = blocks.as_bytes();
		let len = usize::min(data.len(), desc.content_size as usize);
		Ok(data[..len].to_vec())
	}

	/// Decrypts the contents of the given file descriptor into the dest buffer.
	///
	/// The key is not required to be the same as used to open the PAK file.
	///
	/// # Notes
	///
	/// Every call decrypts and authenticates the entire section. If performance is important,
	/// consider [`read_section`](Self::read_section) and manually extract the data.
	pub fn read_into(&self, desc: &Descriptor, key: &Key, byte_offset: usize, dest: &mut [u8]) -> Result<(), ErrorKind> {
		if !desc.is_file() {
			return Err(ErrorKind::InvalidInput);
		}

		let blocks = read_section(&self.blocks, &desc.section, key)?;

		// Figure out which part of the blocks to copy
		let data = match blocks.as_bytes().get(byte_offset..byte_offset + dest.len()) {
			Some(data) => data,
			None => return Err(ErrorKind::InvalidInput),
		};

		// Copy the data to its destination
		dest.copy_from_slice(data);

		Ok(())
	}
}
