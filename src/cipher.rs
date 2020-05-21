/*!
SPECK128/128
============

https://nsacyber.github.io/simon-speck/implementations/ImplementationGuide1.1.pdf
*/

const ROUNDS: usize = 32;

macro_rules! R {
	($x:expr, $y:expr, $k:expr) => {
		$x = $x.rotate_right(8).wrapping_add($y) ^ $k;
		$y = $y.rotate_left(3) ^ $x;
	};
}

macro_rules! IR {
	($x:expr, $y:expr, $k:expr) => {
		$y = ($y ^ $x).rotate_right(3);
		$x = ($x ^ $k).wrapping_sub($y).rotate_left(8);
	};
}

#[inline(never)]
pub const fn expand(key: [u64; 2]) -> [u64; ROUNDS] {
	let [mut b, mut a] = key;
	// FIXME! LLVM does not understand rk is fully overwritten and emits zero initialization code
	let mut rk = [0; ROUNDS];
	let mut i = 0;
	while i < ROUNDS {
		rk[i] = a;
		R!(b, a, i as u64);
		i += 1;
	}
	rk
}

#[inline(never)]
pub const fn encrypt(pt: [u64; 2], rk: &[u64; ROUNDS]) -> [u64; 2] {
	let [mut y, mut x] = pt;
	let mut i = 0;
	while i < ROUNDS {
		R!(y, x, rk[i]);
		i += 1;
	}
	[y, x]
}

#[allow(dead_code)]
#[inline(never)]
pub const fn decrypt(ct: [u64; 2], rk: &[u64; ROUNDS]) -> [u64; 2] {
	let [mut y, mut x] = ct;
	let mut i = ROUNDS;
	while i > 0 {
		i -= 1;
		IR!(y, x, rk[i]);
	}
	[y, x]
}

#[test]
fn test_vectors() {
	let key = [0x0f0e0d0c0b0a0908, 0x0706050403020100];
	let rk = expand(key);
	let plaintext = [0x6c61766975716520, 0x7469206564616d20];
	let ciphertext = [0xa65d985179783265, 0x7860fedf5c570d18];
	assert_eq!(ciphertext, encrypt(plaintext, &rk));
	assert_eq!(plaintext, decrypt(ciphertext, &rk));
}
