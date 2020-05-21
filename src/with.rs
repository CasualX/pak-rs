use core::ptr;
use core::cell::Cell;
use core::mem::ManuallyDrop;
use core::ops::{Deref, DerefMut};

/// Mutable access to the value inside a Cell.
pub struct With<'a, T> {
	cell: &'a Cell<T>,
	value: ManuallyDrop<T>,
}
impl<'a, T> With<'a, T> {
	#[inline]
	pub unsafe fn new(cell: &'a Cell<T>) -> With<'a, T> {
		// Carefully extract the value and wrap it
		let value = unsafe { ManuallyDrop::new(ptr::read(cell.as_ptr())) };
		With { cell, value }
	}
}
impl<'a, T> Drop for With<'a, T> {
	#[inline]
	fn drop(&mut self) {
		// Carefully write the value back in the cell
		unsafe {
			ptr::write(self.cell.as_ptr(), ptr::read(self.value.deref()));
		}
	}
}
impl<'a, T> Deref for With<'a, T> {
	type Target = T;
	#[inline]
	fn deref(&self) -> &T {
		self.value.deref()
	}
}
impl<'a, T> DerefMut for With<'a, T> {
	#[inline]
	fn deref_mut(&mut self) -> &mut T {
		self.value.deref_mut()
	}
}
