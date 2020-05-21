/*!
# FileIO based PAK file format implementation

Implements the PAK file format using [`std::fs::File`].
*/

use std::{fs, io, io::prelude::*};
use crate::*;

/// Reads a PAK file from a stream.
///
/// This method reads and decrypts the PAK file header.
/// If the header is invalid or its MAC check fails, [`io::ErrorKind::InvalidData`] is returned.
///
/// Then it reads all the blocks in the PAK file as specified by the directory.
pub fn read<F: Read>(mut file: F, key: &Key) -> io::Result<Vec<Block>> {
	// Read the header
	let mut header = Header::zeroed();
	file.read_exact(header.as_bytes_mut())?;

	// Set the encrypted header aside
	let header2 = header;

	// Decrypt and validate the header
	if !crypt::decrypt_header(&mut header, key) {
		return Err(io::Error::from(io::ErrorKind::InvalidData));
	}

	// Use information from the header to calculate the total size of the PAK file
	// This code assumes the directory is the very last thing in the PAK file
	let blocks_len = usize::max(Header::BLOCKS_LEN, header.info.directory.offset as usize + header.info.directory.size as usize * Descriptor::BLOCKS_LEN);
	let mut blocks = vec![Block::default(); blocks_len];

	// Copy the encrypted header into the output since it's already read from the file
	blocks[..Header::BLOCKS_LEN].copy_from_slice(header2.as_ref());

	// Then read the rest of the PAK file
	file.read_exact(blocks[Header::BLOCKS_LEN..].as_bytes_mut())?;

	Ok(blocks)
}

#[inline(always)]
fn read_header(file: &mut fs::File, key: &Key) -> io::Result<(InfoHeader, Directory)> {
	// Read the header
	let mut header = Header::default();
	file.read_exact(header.as_bytes_mut())?;

	// Decrypt the header and validate
	if !crypt::decrypt_header(&mut header, key) {
		Err(io::ErrorKind::InvalidData)?;
	}

	// Read the directory
	file.seek(io::SeekFrom::Start(header.info.directory.offset as u64 * BLOCK_SIZE as u64))?;
	let mut directory = Directory::from(vec![Descriptor::default(); header.info.directory.size as usize]);
	file.read_exact(directory.as_mut().as_bytes_mut())?;

	// Decrypt the directory
	if !crypt::decrypt_section(directory.as_blocks_mut(), &header.info.directory, key) {
		Err(io::ErrorKind::InvalidData)?;
	}

	Ok((header.info, directory))
}

fn read_section(mut file: &fs::File, section: &Section, key: &Key) -> io::Result<Vec<Block>> {
	// Read the data to memory buffer
	let file_offset = section.offset as u64 * BLOCK_SIZE as u64;
	file.seek(io::SeekFrom::Start(file_offset))?;
	let mut blocks = vec![Block::default(); section.size as usize];
	file.read_exact(blocks.as_bytes_mut())?;

	// Decrypt the data inplace
	if !crypt::decrypt_section(&mut blocks, section, key) {
		Err(io::ErrorKind::InvalidData)?;
	}

	Ok(blocks)
}

mod reader;
mod editor;
mod edit_file;

pub use self::reader::FileReader;
pub use self::editor::FileEditor;
pub use self::edit_file::FileEditFile;

#[cfg(test)]
mod tests;
