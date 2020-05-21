use std::{fmt, slice};
use crate::*;

/// Directory editor.
///
/// The directory is a sequence of descriptors encoding a light-weight [TLV structure](https://en.wikipedia.org/wiki/Type-length-value).
#[derive(Clone, Debug, Default)]
#[repr(transparent)]
pub struct Directory(Vec<Descriptor>);

impl AsRef<[Descriptor]> for Directory {
	#[inline]
	fn as_ref(&self) -> &[Descriptor] {
		&self.0
	}
}
impl AsMut<[Descriptor]> for Directory {
	#[inline]
	fn as_mut(&mut self) -> &mut [Descriptor] {
		&mut self.0
	}
}
impl From<Vec<Descriptor>> for Directory {
	#[inline]
	fn from(dir: Vec<Descriptor>) -> Directory {
		Directory(dir)
	}
}
impl From<Directory> for Vec<Descriptor> {
	#[inline]
	fn from(this: Directory) -> Vec<Descriptor> {
		this.0
	}
}

impl Directory {
	pub(crate) fn as_blocks(&self) -> &[Block] {
		unsafe {
			slice::from_raw_parts(self.0.as_ptr() as *const Block, self.0.len() * Descriptor::BLOCKS_LEN)
		}
	}
	pub(crate) fn as_blocks_mut(&mut self) -> &mut [Block] {
		unsafe {
			slice::from_raw_parts_mut(self.0.as_mut_ptr() as *mut Block, self.0.len() * Descriptor::BLOCKS_LEN)
		}
	}

	/// Returns if there are no files or directories.
	#[inline]
	pub fn is_empty(&self) -> bool {
		self.0.is_empty()
	}

	/// Returns the number of [`Descriptor`]s in the directory.
	#[inline]
	pub fn len(&self) -> usize {
		self.0.len()
	}

	/// Finds a descriptor by its path.
	#[inline]
	pub fn find_desc(&self, path: &[u8]) -> Option<&Descriptor> {
		dir::find_desc(&self.0, path)
	}

	/// Finds a file descriptor by its path.
	#[inline]
	pub fn find_file(&self, path: &[u8]) -> Option<&Descriptor> {
		match dir::find_desc(&self.0, path) {
			Some(desc) if desc.is_file() => Some(desc),
			_ => None
		}
	}

	/// Gets the child descriptors of the directory at the given path.
	#[inline]
	pub fn get_children(&self, path: &[u8]) -> Option<&[Descriptor]> {
		dir::find_dir(&self.0, path)
	}

	/// Returns a displayable directory.
	#[inline]
	pub fn display(&self) -> impl '_ + fmt::Display {
		dir::Fmt::new(".", &self.0, &dir::Art::UNICODE)
	}

	/// File system consistency check.
	///
	/// Checks the directory for errors, returns false if there's any inconsistencies.
	/// Detailed information can be found in the log.
	///
	/// The high mark is the highest block index that a file section is allowed.
	#[inline]
	pub fn fsck(&self, high_mark: u32, log: &mut dyn fmt::Write) -> bool {
		dir::fsck(&self.0, high_mark, log)
	}
}
impl Directory {
	/// Creates a new, empty `Directory` instance.
	#[inline]
	pub const fn new() -> Directory {
		Directory(Vec::new())
	}

	// For internal use
	#[inline]
	pub(crate) fn create(&mut self, path: &[u8]) -> &mut Descriptor {
		dir::create(&mut self.0, path)
	}

	/// Creates a symbolic link from the path to the given file descriptor.
	///
	/// Any missing parent directories are automatically created.
	///
	/// Does nothing if the given descriptor is not a file descriptor.
	pub fn create_link(&mut self, path: &[u8], file_desc: &Descriptor) {
		if file_desc.is_file() {
			let desc = dir::create(&mut self.0, path);
			desc.content_size = file_desc.content_size;
			desc.content_type = file_desc.content_type;
			desc.section = file_desc.section;
		}
	}

	/// Creates a directory descriptor at the given path.
	///
	/// Any missing parent directories are automatically created.
	#[inline]
	pub fn create_dir(&mut self, path: &[u8]) {
		let desc = dir::create(&mut self.0, path);
		desc.content_type = 0;
		desc.content_size = 0;
		desc.section = Section::default();
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
	#[inline]
	pub fn remove(&mut self, path: &[u8]) -> Option<Descriptor> {
		dir::remove(&mut self.0, path)
	}

	/// Moves a file descriptor from the src path to the given dest path.
	///
	/// Returns `false` if the src path does not exist or is a directory descriptor.
	/// This method cannot move directory descriptors.
	///
	/// Returns `true` if the move was successful.
	pub fn move_file(&mut self, src_path: &[u8], dest_path: &[u8]) -> bool {
		// Check to make sure it's a file descriptor
		// Moving directory descriptors like this corrupts the directory
		match dir::find_desc(&self.0, src_path) {
			Some(src_desc) if src_desc.is_file() => (),
			_ => return false,
		}

		// Delete the descriptor
		let deleted = match dir::remove(&mut self.0, src_path) {
			Some(deleted) => deleted,
			None => return false,
		};

		let desc = dir::create(&mut self.0, dest_path);
		desc.content_type = deleted.content_type;
		desc.content_size = deleted.content_size;
		desc.section = deleted.section;
		return true;
	}
}

#[cfg(test)]
mod tests;
