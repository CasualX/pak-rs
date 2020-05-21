use std::{fs, io, io::prelude::*};
use crate::*;

/// File file editor.
pub struct FileEditFile<'a> {
	pub(super) file: &'a fs::File,
	pub(super) desc: &'a mut Descriptor,
	pub(super) high_mark: &'a mut u32,
}

impl<'a> FileEditFile<'a> {
	/// Gets the file descriptor as-is.
	#[inline]
	pub fn descriptor(&self) -> &Descriptor {
		self.desc
	}

	/// Sets the content type and size for this file descriptor.
	///
	/// Note that a content type of `0` gets overwritten by a type of `1`.
	pub fn set_content(&mut self, content_type: u32, content_size: u32) -> &mut FileEditFile<'a> {
		self.desc.content_type = u32::max(1, content_type); // zero is reserved for directory descriptors...
		self.desc.content_size = content_size;
		return self;
	}

	/// Assigns an existing section object to this file descriptor.
	///
	/// This can be used to make different descriptors point to the same data.
	pub fn set_section(&mut self, section: &Section) -> &mut FileEditFile<'a> {
		self.desc.section = *section;
		return self;
	}

	/// Allocates and assigns space for the data.
	///
	/// The size allocated is defined by a previous call to [`set_content`](Self::set_content)'s `content_size` argument.
	///
	/// The space allocated is logically uninitialized and must be initialized with [`write_data`](Self::write_data) or [`zero_data`](Self::zero_data).
	pub fn allocate_data(&mut self) -> &mut FileEditFile<'a> {
		// Simple bump allocate from the file
		self.desc.section.offset = *self.high_mark;
		self.desc.section.size = bytes2blocks(self.desc.content_size);

		// Bump the allocation
		// FIXME! Overflow??
		*self.high_mark += self.desc.section.size;

		return self;
	}

	/// Copies and encrypts the data with the given key into the address specified by this file descriptor.
	pub fn write_data(&mut self, data: &[u8], key: &Key) -> io::Result<&mut FileEditFile<'a>> {
		// Seek to this section's file offset
		let file_offset = self.desc.section.offset as u64 * BLOCK_SIZE as u64;
		self.file.seek(io::SeekFrom::Start(file_offset))?;

		// Temp allocation to encrypt the data
		let mut blocks = vec![Block::default(); self.desc.section.size as usize];

		// Copy the data in the temp allocation
		let len = usize::min(blocks.as_bytes().len(), data.len());
		blocks.as_bytes_mut()[..len].copy_from_slice(&data[..len]);

		// Encrypt the data inplace
		crypt::encrypt_section(&mut blocks, &mut self.desc.section, key);

		// Write the data to the file
		let result = self.file.write_all(blocks.as_bytes());

		drop(blocks);
		result.map(|()| self)
	}

	/// Initialize the data with zeroes.
	pub fn zero_data(&mut self, key: &Key) -> io::Result<&mut FileEditFile<'a>> {
		// Seek to this section's file offset
		let file_offset = self.desc.section.offset as u64 * BLOCK_SIZE as u64;
		self.file.seek(io::SeekFrom::Start(file_offset))?;

		// Temp allocation to encrypt the zeroes
		let mut blocks = vec![Block::default(); self.desc.section.size as usize];

		// Encrypt the zeroes inplace
		crypt::encrypt_section(&mut blocks, &mut self.desc.section, key);

		// Write the zeroes to the file
		let result = self.file.write_all(blocks.as_bytes());

		drop(blocks);
		result.map(|()| self)
	}

	/// Reencrypts the data.
	///
	/// The file must be initialized (either through `init_data` or `zero_data`) before it can be updated.
	///
	/// # Consistency guarantees
	///
	/// The file contents are updated inplace.
	/// In the case of a failure (forced crash or power loss) the consistency is not guaranteed.
	///
	/// If consistency is important, consider removing & creating the file again instead.
	pub fn reencrypt_data(&mut self, old_key: &Key, key: &Key) -> io::Result<()> {
		// Read the file to memory buffer
		let file_offset = self.desc.section.offset as u64 * BLOCK_SIZE as u64;
		self.file.seek(io::SeekFrom::Start(file_offset))?;
		let mut blocks = vec![Block::default(); self.desc.section.size as usize];
		self.file.read_exact(blocks.as_bytes_mut())?;

		// Decrypt the data inplace
		if !crypt::decrypt_section(&mut blocks, &self.desc.section, old_key) {
			// Leave the data alone if the MAC is invalid
			Err(io::ErrorKind::InvalidData)?;
		}

		// Encrypt the data inplace
		crypt::encrypt_section(&mut blocks, &mut self.desc.section, key);

		// Write the data back to the file
		self.file.seek(io::SeekFrom::Start(file_offset))?;
		self.file.write_all(blocks.as_bytes())?;

		Ok(())
	}
}
