use crate::*;

/// Memory file editor.
///
/// This type provides advanced capabilities for editing a file.
/// Incorrect usage may result in corrupted file contents or even corrupt the entire PAK file.
pub struct MemoryEditFile<'a> {
	pub(super) desc: &'a mut Descriptor,
	pub(super) blocks: &'a mut Vec<Block>,
}

impl<'a> MemoryEditFile<'a> {
	/// Gets the file descriptor as-is.
	#[inline]
	pub fn descriptor(&self) -> &Descriptor {
		self.desc
	}

	/// Sets the content type and size for this file descriptor.
	///
	/// Note that a content type of `0` gets overwritten by a type of `1`.
	pub fn set_content(&mut self, content_type: u32, content_size: u32) -> &mut MemoryEditFile<'a> {
		self.desc.content_type = u32::max(1, content_type); // zero is reserved for directory descriptors...
		self.desc.content_size = content_size;
		return self;
	}

	/// Assigns an existing section object to this file descriptor.
	///
	/// This can be used to make different descriptors point to the same file contents.
	pub fn set_section(&mut self, section: &Section) -> &mut MemoryEditFile<'a> {
		self.desc.section = *section;
		return self;
	}

	/// Allocates and assigns space for the file contents.
	///
	/// The size allocated is defined by a previous call to `set_content`'s content_size argument.
	///
	/// The space allocated is logically uninitialized and must be initialized with a call to `write_data` or `init_zero`.
	pub fn allocate_data(&mut self) -> &mut MemoryEditFile<'a> {
		let size = bytes2blocks(self.desc.content_size);

		// Simple bump allocate from the blocks Vec
		self.desc.section.offset = self.blocks.len() as u32;
		self.desc.section.size = size;

		// In the case of overflow... Do nothing?
		// Writing data into the allocation will fail
		if let Some(new_len) = self.blocks.len().checked_add(size as usize) {
			// Should be overwritten by `write_data` or `zero_data`
			self.blocks.resize(new_len, Block::default());
		}

		return self;
	}

	/// Copies and encrypts the data with the given key into the address specified by this file descriptor.
	///
	/// # Panics
	///
	/// This method assumes the section is correctly initialized (either through `set_section` or `allocate`).
	pub fn write_data(&mut self, data: &[u8], key: &Key) -> &mut MemoryEditFile<'a> {
		let blocks = &mut self.blocks[self.desc.section.range_usize()];

		// Copy the data into the allocation
		let len = usize::min(blocks.as_bytes().len(), data.len());
		blocks.as_bytes_mut()[..len].copy_from_slice(&data[..len]);

		// Encrypt the data inplace
		crypt::encrypt_section(blocks, &mut self.desc.section, key);

		return self;
	}

	/// Initialize the data with zeroes.
	pub fn zero_data(&mut self, key: &Key) -> &mut MemoryEditFile<'a> {
		let blocks = &mut self.blocks[self.desc.section.range_usize()];

		// Zero the data
		blocks.fill(Block::default());

		// Encrypt the data inplace
		crypt::encrypt_section(blocks, &mut self.desc.section, key);

		return self;
	}

	/// Reencrypts the data.
	///
	/// The file must be initialized (either through `write_data` or `zero_data`) before it can be updated.
	///
	/// # Panics
	///
	/// This method assumes the section is correctly initialized (either through `set_section` or `allocate`).
	pub fn reencrypt_data(&mut self, old_key: &Key, key: &Key) {
		let blocks = &mut self.blocks[self.desc.section.range_usize()];

		let old_mac = self.desc.section.mac;

		// Simply decrypt and encrypt again
		let is_valid = crypt::decrypt_section(blocks, &self.desc.section, old_key);
		crypt::encrypt_section(blocks, &mut self.desc.section, key);

		// If the MAC wasn't valid to begin with, keep it invalid
		if !is_valid {
			self.desc.section.mac = old_mac;
		}
	}
}
