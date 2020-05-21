use crate::*;

const EXAMPLE: &[u8] = include_str!("../../tests/data/example.txt").as_bytes();

#[test]
fn test_simple() {
	let ref key = [1, 2];

	// Create a new PAK file and finish it
	let (blocks, _) = MemoryEditor::new().finish(key);

	// Re-open the PAK file for editing
	let mut edit = MemoryEditor::from_blocks(blocks, key).expect("failed to edit");

	// Add the test file
	edit.create_file(b"example", EXAMPLE, key);

	// Finish the test PAK file
	let (blocks, _) = edit.finish(key);

	// Re-open the PAK file for reading
	let reader = MemoryReader::from_blocks(blocks, key).expect("failed to read");

	// Check the directory listing
	let dir = &*reader;
	let listing = dir::to_string(".", dir.as_ref(), &dir::Art::ASCII);
	assert_eq!(dbg!(listing), "./\n`  example\n");

	// Check the test file
	let desc = reader.find_file(b"example").expect("example file not found");
	let example = reader.read_data(desc, key).expect("failed to read example");
	assert_eq!(example, EXAMPLE);
}
