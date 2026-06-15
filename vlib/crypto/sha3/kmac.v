// Copyright (c) 2023 Kim Shrier. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

// KMAC is the keyed message authentication code defined in NIST SP 800-185.
// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf

module sha3

const kmac_name = 'KMAC'.bytes()

// KMAC is a keyed hash (MAC) built on cSHAKE. It supports both the
// fixed-output KMAC128/KMAC256 and the arbitrary-output KMACXOF128/KMACXOF256
// variants. Create one with `new_kmac128`, `new_kmac256`, `new_kmac128xof`
// or `new_kmac256xof`, absorb the message with `write`, then obtain the tag
// with `sum` (fixed output) or `read` (XOF output).
@[noinit]
pub struct KMAC {
mut:
	s          &Shake = unsafe { nil }
	output_len int
	finalized  bool
}

// new_kmac128 returns a KMAC128 instance keyed with `key` and customized with
// `custom`, producing `output_len` bytes of output. See NIST SP 800-185 sec 4.
pub fn new_kmac128(key []u8, custom []u8, output_len int) &KMAC {
	return new_kmac(xof_rate_128, key, custom, output_len)
}

// new_kmac256 returns a KMAC256 instance keyed with `key` and customized with
// `custom`, producing `output_len` bytes of output. See NIST SP 800-185 sec 4.
pub fn new_kmac256(key []u8, custom []u8, output_len int) &KMAC {
	return new_kmac(xof_rate_256, key, custom, output_len)
}

// new_kmac128xof returns a KMACXOF128 instance keyed with `key` and customized
// with `custom`. Output of any length is squeezed with `read`.
// See NIST SP 800-185 sec 4.3.1.
pub fn new_kmac128xof(key []u8, custom []u8) &KMAC {
	return new_kmac(xof_rate_128, key, custom, 0)
}

// new_kmac256xof returns a KMACXOF256 instance keyed with `key` and customized
// with `custom`. Output of any length is squeezed with `read`.
// See NIST SP 800-185 sec 4.3.1.
pub fn new_kmac256xof(key []u8, custom []u8) &KMAC {
	return new_kmac(xof_rate_256, key, custom, 0)
}

fn new_kmac(rate int, key []u8, custom []u8, output_len int) &KMAC {
	mut sh := new_cshake(rate, kmac_name, custom)
	sh.write(bytepad(encode_string(key), rate))
	return &KMAC{
		s:          sh
		output_len: output_len
	}
}

// write absorbs more message bytes into the KMAC state.
pub fn (mut k KMAC) write(data []u8) {
	k.s.write(data)
}

// sum finalizes the fixed-output KMAC and returns the `output_len`-byte tag.
// It must not be used on a KMACXOF instance; use `read` for those.
pub fn (mut k KMAC) sum() []u8 {
	if !k.finalized {
		k.s.write(right_encode(u64(k.output_len) * 8))
		k.finalized = true
	}
	return k.s.read(k.output_len)
}

// read squeezes `out_len` bytes from a KMACXOF instance. On the first call the
// state is finalized; further calls keep squeezing additional output.
pub fn (mut k KMAC) read(out_len int) []u8 {
	if !k.finalized {
		k.s.write(right_encode(0))
		k.finalized = true
	}
	return k.s.read(out_len)
}

// kmac128 returns the `output_len`-byte KMAC128 tag of `data` using `key` and
// customization string `custom`.
pub fn kmac128(key []u8, data []u8, custom []u8, output_len int) []u8 {
	mut k := new_kmac128(key, custom, output_len)
	k.write(data)
	return k.sum()
}

// kmac256 returns the `output_len`-byte KMAC256 tag of `data` using `key` and
// customization string `custom`.
pub fn kmac256(key []u8, data []u8, custom []u8, output_len int) []u8 {
	mut k := new_kmac256(key, custom, output_len)
	k.write(data)
	return k.sum()
}

// kmac128xof returns `output_len` bytes of KMACXOF128 output of `data` using
// `key` and customization string `custom`.
pub fn kmac128xof(key []u8, data []u8, custom []u8, output_len int) []u8 {
	mut k := new_kmac128xof(key, custom)
	k.write(data)
	return k.read(output_len)
}

// kmac256xof returns `output_len` bytes of KMACXOF256 output of `data` using
// `key` and customization string `custom`.
pub fn kmac256xof(key []u8, data []u8, custom []u8, output_len int) []u8 {
	mut k := new_kmac256xof(key, custom)
	k.write(data)
	return k.read(output_len)
}
