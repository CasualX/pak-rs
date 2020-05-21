use crate::*;

#[test]
fn test_create_remove_create_links() {
	let mut directory = Directory::from(vec![
		Descriptor::dir(b"a", 2),
		Descriptor::dir(b"b", 1),
		Descriptor::file(b"example"),
	]);

	let example1 = directory.as_ref()[2];
	directory.create_link(b"aa/bb/example", &example1);
	let example2 = directory.remove(b"a/b/example").unwrap();
	directory.create_link(b"a/b/example", &example2);

	dbg!(directory);
}
