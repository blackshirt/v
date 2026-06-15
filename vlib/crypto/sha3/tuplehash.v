// Copyright (c) 2023 Kim Shrier. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

// TupleHash is the tuple hash function defined in NIST SP 800-185. It hashes a
// sequence of byte strings unambiguously, so that the hash of the tuple
// ("abc", "d") differs from the hash of ("ab", "cd").
// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf

module sha3

const tuplehash_name = 'TupleHash'.bytes()

// TupleHash hashes a sequence of byte strings (a tuple) built on cSHAKE. It
// supports both the fixed-output TupleHash128/TupleHash256 and the
// arbitrary-output TupleHashXOF128/TupleHashXOF256 variants. Create one with
// `new_tuplehash128`, `new_tuplehash256`, `new_tuplehash128xof` or
// `new_tuplehash256xof`, add each tuple element with `write`, then obtain the
// digest with `sum` (fixed output) or `read` (XOF output).
@[noinit]
pub struct TupleHash {
mut:
	s          &Shake = unsafe { nil }
	output_len int
	finalized  bool
}

// new_tuplehash128 returns a TupleHash128 instance customized with `custom`,
// producing `output_len` bytes of output. See NIST SP 800-185 sec 5.
pub fn new_tuplehash128(custom []u8, output_len int) &TupleHash {
	return new_tuplehash(xof_rate_128, custom, output_len)
}

// new_tuplehash256 returns a TupleHash256 instance customized with `custom`,
// producing `output_len` bytes of output. See NIST SP 800-185 sec 5.
pub fn new_tuplehash256(custom []u8, output_len int) &TupleHash {
	return new_tuplehash(xof_rate_256, custom, output_len)
}

// new_tuplehash128xof returns a TupleHashXOF128 instance customized with
// `custom`. Output of any length is squeezed with `read`.
// See NIST SP 800-185 sec 5.3.1.
pub fn new_tuplehash128xof(custom []u8) &TupleHash {
	return new_tuplehash(xof_rate_128, custom, 0)
}

// new_tuplehash256xof returns a TupleHashXOF256 instance customized with
// `custom`. Output of any length is squeezed with `read`.
// See NIST SP 800-185 sec 5.3.1.
pub fn new_tuplehash256xof(custom []u8) &TupleHash {
	return new_tuplehash(xof_rate_256, custom, 0)
}

fn new_tuplehash(rate int, custom []u8, output_len int) &TupleHash {
	return &TupleHash{
		s:          new_cshake(rate, tuplehash_name, custom)
		output_len: output_len
	}
}

// write adds one tuple element. Each call appends the unambiguous encoding of
// `element`, so the order and boundaries of the elements affect the result.
pub fn (mut t TupleHash) write(element []u8) {
	t.s.write(encode_string(element))
}

// sum finalizes the fixed-output TupleHash and returns the `output_len`-byte
// digest. It must not be used on a TupleHashXOF instance; use `read` for those.
pub fn (mut t TupleHash) sum() []u8 {
	if !t.finalized {
		t.s.write(right_encode(u64(t.output_len) * 8))
		t.finalized = true
	}
	return t.s.read(t.output_len)
}

// read squeezes `out_len` bytes from a TupleHashXOF instance. On the first call
// the state is finalized; further calls keep squeezing additional output.
pub fn (mut t TupleHash) read(out_len int) []u8 {
	if !t.finalized {
		t.s.write(right_encode(0))
		t.finalized = true
	}
	return t.s.read(out_len)
}

// tuplehash128 returns the `output_len`-byte TupleHash128 digest of the tuple
// `data` using customization string `custom`.
pub fn tuplehash128(data [][]u8, custom []u8, output_len int) []u8 {
	mut t := new_tuplehash128(custom, output_len)
	for element in data {
		t.write(element)
	}
	return t.sum()
}

// tuplehash256 returns the `output_len`-byte TupleHash256 digest of the tuple
// `data` using customization string `custom`.
pub fn tuplehash256(data [][]u8, custom []u8, output_len int) []u8 {
	mut t := new_tuplehash256(custom, output_len)
	for element in data {
		t.write(element)
	}
	return t.sum()
}

// tuplehash128xof returns `output_len` bytes of TupleHashXOF128 output of the
// tuple `data` using customization string `custom`.
pub fn tuplehash128xof(data [][]u8, custom []u8, output_len int) []u8 {
	mut t := new_tuplehash128xof(custom)
	for element in data {
		t.write(element)
	}
	return t.read(output_len)
}

// tuplehash256xof returns `output_len` bytes of TupleHashXOF256 output of the
// tuple `data` using customization string `custom`.
pub fn tuplehash256xof(data [][]u8, custom []u8, output_len int) []u8 {
	mut t := new_tuplehash256xof(custom)
	for element in data {
		t.write(element)
	}
	return t.read(output_len)
}
