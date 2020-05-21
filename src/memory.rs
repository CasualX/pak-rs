use std::slice;
use std::io::ErrorKind;
use crate::*;

// Decrypts and authenticates a section.
// Returns an error if the section range or MAC is incorrect.
fn read_section(blocks: &[Block], section: &Section, key: &Key) -> Result<Vec<Block>, ErrorKind> {
	let blocks = match blocks.get(section.range_usize()) {
		Some(blocks) => blocks,
		None => return Err(ErrorKind::InvalidInput),
	};

	let mut blocks = blocks.to_vec();
	if !crypt::decrypt_section(&mut blocks, section, key) {
		return Err(ErrorKind::InvalidData);
	}

	Ok(blocks)
}

// Decrypts and authenticates the header and the directory.
// Returns an the original blocks on any bounds errors or MAC checks fail.
fn from_blocks(mut blocks: Vec<Block>, key: &Key) -> Result<(Vec<Block>, Directory), Vec<Block>> {
	// The blocks must contain at least space for the header ref$1
	if blocks.len() < Header::BLOCKS_LEN {
		return Err(blocks);
	}

	// Decrypt the header
	let mut header: Header = blocks.as_data_view_mut().copy(0);
	if !crypt::decrypt_header(&mut header, key) {
		// MAC is incorrect!
		return Err(blocks);
	}

	// Extract the directory
	let dir_start = header.info.directory.offset as usize;
	let dir_end = dir_start + header.info.directory.size as usize * Descriptor::BLOCKS_LEN;
	let dir_blocks = match blocks.get_mut(dir_start..dir_end) {
		Some(dir_blocks) => dir_blocks,
		None => return Err(blocks),
	};

	// Decrypt the directory
	crypt::decrypt_section(dir_blocks, &header.info.directory, key);

	// Reinterpret the directory
	let dir = unsafe {
		slice::from_raw_parts(dir_blocks.as_ptr() as *const Descriptor, header.info.directory.size as usize)
	};
	let directory = Directory::from(dir.to_vec());

	// Truncate the blocks to trim the directory
	if blocks.len() == dir_end {
		blocks.truncate(dir_start);
	}

	Ok((blocks, directory))
}

/// Casts the blocks to byte slice.
#[inline]
pub fn as_bytes(blocks: &[Block]) -> &[u8] {
	blocks.as_bytes()
}
/// Casts the blocks to mutable byte slice.
#[inline]
pub fn as_bytes_mut(blocks: &mut [Block]) -> &mut [u8] {
	blocks.as_bytes_mut()
}

mod reader;
mod editor;
mod edit_file;

pub use self::reader::*;
pub use self::editor::*;
pub use self::edit_file::*;

#[cfg(test)]
mod tests;
