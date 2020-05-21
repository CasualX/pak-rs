/*
Authenticated Encryption
========================

Bring Your Own Authenticated Encryption based on https://eprint.iacr.org/2019/712.pdf

The chosen cipher is SPECK128/128, the mode of operation is CTR.
The authentication is CBC-MAC over the ciphertext.

```text
                                     PLAINTEXT(n)
                                          │
                                          │
                     ┌─────────┐          ▼
                     │         │
         NONCE(n)───►│ ENCRYPT ├───────►  ⊕  ──────► CIPHERTEXT(n)
            │        │         │                          │
            ▼        └─────────┘                          │
        ┌───────┐         ▲           ┌─────────┐         ▼
        │       │         │           │         │
        │  CTR  │        KEY ────────►│ ENCRYPT │◄──────  ⊕
        │       │                     │         │
        └───┬───┘                     └────┬────┘         ▲
            │                              │              │
            ▼                              ▼              │
        NONCE(n+1)                      MAC(n+1)        MAC(n)
```
*/

use std::slice;
use crate::*;
use dataview::Pod;

fn xor(a: Block, b: Block) -> Block {
	[a[0] ^ b[0], a[1] ^ b[1]]
}
fn counter(nonce: Block, i: usize) -> Block {
	[nonce[0], nonce[1].wrapping_add(i as u64)]
}
fn random(blocks: &mut [Block]) {
	if let Err(_) = getrandom::getrandom(blocks.as_bytes_mut()) {
		random_error()
	}
}

#[inline(never)]
#[cold]
fn random_error() -> ! {
	panic!("random unavailable")
}

#[inline(never)]
pub fn encrypt_section(blocks: &mut [Block], section: &mut Section, &key: &Key) {
	// Every encryption reinitialize with a random nonce
	random(slice::from_mut(&mut section.nonce));

	// Derive new keys and nonces and expand the round keys
	let rk = cipher::expand(key);
	let rke = cipher::expand(cipher::encrypt(counter(section.nonce, 0), &rk));
	let rkm = cipher::expand(cipher::encrypt(counter(section.nonce, 1), &rk));
	let ne = cipher::encrypt(counter(section.nonce, 2), &rk);
	let nm = cipher::encrypt(counter(section.nonce, 3), &rk);

	let mut mac = nm;
	for i in 0..blocks.len() {
		let pt = blocks[i];
		let ct = xor(cipher::encrypt(counter(ne, i), &rke), pt);
		mac = cipher::encrypt(xor(mac, ct), &rkm);
		blocks[i] = ct;
	}
	section.mac = mac;
}

#[inline(never)]
pub fn decrypt_section(blocks: &mut [Block], section: &Section, &key: &Key) -> bool {
	// Derive new keys and nonces and expand the round keys
	let rk = cipher::expand(key);
	let rke = cipher::expand(cipher::encrypt(counter(section.nonce, 0), &rk));
	let rkm = cipher::expand(cipher::encrypt(counter(section.nonce, 1), &rk));
	let ne = cipher::encrypt(counter(section.nonce, 2), &rk);
	let nm = cipher::encrypt(counter(section.nonce, 3), &rk);

	let mut mac = nm;
	for i in 0..blocks.len() {
		let ct = blocks[i];
		let pt = xor(cipher::encrypt(counter(ne, i), &rke), ct);
		mac = cipher::encrypt(xor(mac, ct), &rkm);
		blocks[i] = pt;
	}

	// Constant-time comparison of the mac
	section.mac[0] ^ mac[0] | section.mac[1] ^ mac[1] == 0
}

#[test]
fn test_roundtrip() {
	let data = [[1, 2], [3, 4], [5, !0]];
	let ref key = [13, 42];

	let mut blocks = data;

	let mut section = Section {
		offset: 0,
		size: 3,
		nonce: Block::default(),
		mac: Block::default(),
	};

	encrypt_section(&mut blocks, &mut section, key);
	eprintln!("{:#?}", section);

	assert!(decrypt_section(&mut blocks, &section, key));
	assert_eq!(data, blocks);
}

#[inline]
pub fn encrypt_header(header: &mut Header, key: &Key) {
	header.info.version = InfoHeader::VERSION;
	header.info._unused = 0;
	let mut section = Section::default();
	crypt::encrypt_section(header.info.as_mut(), &mut section, key);
	header.nonce = section.nonce;
	header.mac = section.mac;
}

#[inline]
pub fn decrypt_header(header: &mut Header, key: &Key) -> bool {
	let section = Section {
		nonce: header.nonce,
		mac: header.mac,
		..Header::SECTION
	};
	crypt::decrypt_section(header.info.as_mut(), &section, key)
		&& header.info.version == InfoHeader::VERSION
}
