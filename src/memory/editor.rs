use std::ops;
use crate::*;
use super::*;

/// Memory editor.
///
/// This implementation keeps the entire PAK file in memory.
#[derive(Clone, Debug)]
pub struct MemoryEditor {
	pub(super) blocks: Vec<Block>,
	pub(super) directory: Directory,
}

impl MemoryEditor {
	/// Creates a new `MemoryEditor` instance.
	pub fn new() -> MemoryEditor {
		// The blocks must contain at least space for the header ref$1
		let blocks = vec![Block::default(); Header::BLOCKS_LEN];
		let directory = Directory::from(Vec::new());
		MemoryEditor { blocks, directory }
	}

	/// Parses the bytes as the PAK file format for editing.
	///
	/// # Notes
	///
	/// The editor has specific alignment requirements for the buffer.
	/// For this reason the entire byte array will be copied to an internal buffer.
	///
	/// # Errors
	///
	/// * [`ErrorKind::InvalidInput`]: Bytes length is not a multiple of the block size.
	/// * [`ErrorKind::InvalidData`]: Incorrect version info or authentication checks failed.
	pub fn from_bytes(bytes: &[u8], key: &Key) -> Result<MemoryEditor, ErrorKind> {
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
			Ok((blocks, directory)) => Ok(MemoryEditor { blocks, directory }),
			Err(_) => unimplemented!(),
		}
	}

	/// Parses the blocks as the PAK file format for editing.
	pub fn from_blocks(blocks: Vec<Block>, key: &Key) -> Result<MemoryEditor, Vec<Block>> {
		from_blocks(blocks, key).map(|(blocks, directory)| MemoryEditor { blocks, directory })
	}
}

impl ops::Deref for MemoryEditor {
	type Target = Directory;
	#[inline]
	fn deref(&self) -> &Directory {
		&self.directory
	}
}
impl ops::DerefMut for MemoryEditor {
	fn deref_mut(&mut self) -> &mut Directory {
		&mut self.directory
	}
}

impl MemoryEditor {
	/// Highest block index containing file data.
	#[inline]
	pub fn high_mark(&self) -> u32 {
		self.blocks.len() as u32
	}

	/// Creates a file descriptor at the given path.
	///
	/// Any missing parent directories are automatically created.
	pub fn edit_file(&mut self, path: &[u8]) -> MemoryEditFile<'_> {
		let desc = self.directory.create(path);
		let blocks = &mut self.blocks;
		MemoryEditFile { blocks, desc }
	}

	/// Creates a file at the given path.
	///
	/// The file is assigned a content_type of `1`.
	/// A new section is allocated and the data is encrypted and written into the section.
	///
	/// Any missing parent directories are automatically created.
	///
	/// If the data's len is greater than 4 GiB it is truncated as its size is stored in a `u32`.
	pub fn create_file(&mut self, path: &[u8], data: &[u8], key: &Key) -> &Descriptor {
		let mut edit_file = self.edit_file(path);
		edit_file.set_content(1, data.len() as u32);
		edit_file.allocate_data().write_data(data, key);
		edit_file.desc
	}

	/// Decrypts the section.
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

	/// Compacts the referenced data blocks from file descriptors.
	///
	/// Removing files only removes their descriptors, leaving unreadable garbage around.
	/// The cryptographic nonce has been erased making it no longer possible to recover the file data.
	/// This method reclaims the space left behind by deleted files.
	///
	/// Any file descriptors with an invalid section object has their section object zeroed.
	pub fn gc(&mut self) {
		let mut blocks = vec![Block::default(); Header::BLOCKS_LEN];

		for desc in self.directory.as_mut() {
			if desc.is_file() {
				let offset = blocks.len();
				if let Some(data) = self.blocks.get(desc.section.range_usize()) {
					blocks.extend_from_slice(data);
					desc.section.offset = offset as u32;
				}
				else {
					// Not much to do when we find an invalid descriptor...
					desc.section = Section::default();
				}
			}
		}

		self.blocks = blocks;
	}

	/// Finish editing the PAK file.
	///
	/// Initializes the header, encrypts the directory and appends it to the blocks.
	/// Returns the encrypted PAK file and the unencrypted directory for inspection.
	pub fn finish(self, key: &Key) -> (Vec<Block>, Directory) {
		let MemoryEditor { mut blocks, directory } = self;

		{
			// Ensure enough room for the header ref$1
			if blocks.len() < Header::BLOCKS_LEN {
				let padding = &[[0, 0]; Header::BLOCKS_LEN];
				blocks.extend_from_slice(&padding[..Header::BLOCKS_LEN - blocks.len()]);
			}

			// Keep track if the highest block index before the directory starts
			let high_mark = blocks.len();
			let dir_size = directory.len();

			// Append the directory (unencrypted)
			blocks.extend_from_slice(directory.as_blocks());

			// Satisfy the borrow checker
			let (blocks, directory) = blocks.split_at_mut(high_mark);

			// Safety: We've ensured there's at least enough blocks for the header before the high_mark
			let header: &mut Header = blocks.as_data_view_mut().read_mut(0);

			// Write a template header
			*header = Header {
				nonce: Block::default(),
				mac: Block::default(),
				info: InfoHeader {
					version: InfoHeader::VERSION,
					_unused: 0,
					directory: Section {
						offset: high_mark as u32,
						size: dir_size as u32,
						nonce: Block::default(),
						mac: Block::default(),
					},
				},
			};

			// Encrypt the directory
			crypt::encrypt_section(directory, &mut header.info.directory, key);

			// Encrypt the header
			let mut section = Header::SECTION;
			crypt::encrypt_section(header.info.as_mut(), &mut section, key);

			header.nonce = section.nonce;
			header.mac = section.mac;
		}

		(blocks, directory)
	}
}
