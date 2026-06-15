// Copyright (c) 2023 Kim Shrier. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

// cSHAKE is the customizable SHAKE function defined in NIST SP 800-185.
// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf

module sha3

// cshake_ds is the domain separator used by cSHAKE, KMAC and TupleHash.
// When both the function-name and customization strings are empty, cSHAKE
// reduces to plain SHAKE which keeps the 0x1f separator instead.
const cshake_ds = u8(0x04)

// left_encode encodes the non-negative integer `x` as defined in
// NIST SP 800-185 sec 2.3.1. The first output byte holds the number of
// encoding bytes that follow, then `x` is stored big-endian.
fn left_encode(x u64) []u8 {
	mut be := []u8{}
	mut v := x
	for {
		be << u8(v)
		v >>= 8
		if v == 0 {
			break
		}
	}
	n := be.len
	mut out := []u8{cap: n + 1}
	out << u8(n)
	for i := n - 1; i >= 0; i-- {
		out << be[i]
	}
	return out
}

// right_encode encodes the non-negative integer `x` as defined in
// NIST SP 800-185 sec 2.3.1. It is the same as left_encode except the
// length byte is appended after the big-endian value bytes.
fn right_encode(x u64) []u8 {
	mut be := []u8{}
	mut v := x
	for {
		be << u8(v)
		v >>= 8
		if v == 0 {
			break
		}
	}
	n := be.len
	mut out := []u8{cap: n + 1}
	for i := n - 1; i >= 0; i-- {
		out << be[i]
	}
	out << u8(n)
	return out
}

// encode_string encodes the byte string `s` as defined in
// NIST SP 800-185 sec 2.3.2: left_encode of the bit length followed by `s`.
fn encode_string(s []u8) []u8 {
	mut out := left_encode(u64(s.len) * 8)
	out << s
	return out
}

// bytepad prepends left_encode(w) to `x` and zero-pads the result so its
// length is a multiple of `w`, as defined in NIST SP 800-185 sec 2.3.3.
fn bytepad(x []u8, w int) []u8 {
	mut out := left_encode(u64(w))
	out << x
	for out.len % w != 0 {
		out << u8(0x00)
	}
	return out
}

// new_cshake128 returns a new Shake instance for the cSHAKE128 function as
// defined in NIST SP 800-185. `n` is the function-name string (normally empty
// for direct use, it is reserved for NIST defined functions) and `s` is the
// customization string. When both are empty, cSHAKE128 is identical to
// SHAKE-128.
pub fn new_cshake128(n []u8, s []u8) &Shake {
	return new_cshake(xof_rate_128, n, s)
}

// new_cshake256 returns a new Shake instance for the cSHAKE256 function as
// defined in NIST SP 800-185. `n` is the function-name string (normally empty
// for direct use, it is reserved for NIST defined functions) and `s` is the
// customization string. When both are empty, cSHAKE256 is identical to
// SHAKE-256.
pub fn new_cshake256(n []u8, s []u8) &Shake {
	return new_cshake(xof_rate_256, n, s)
}

fn new_cshake(rate int, n []u8, s []u8) &Shake {
	if n.len == 0 && s.len == 0 {
		// cSHAKE with empty strings is plain SHAKE (domain separator 0x1f)
		return &Shake{
			rate: rate
		}
	}

	mut sh := &Shake{
		rate: rate
		ds:   cshake_ds
	}
	mut prefix := encode_string(n)
	prefix << encode_string(s)
	sh.write(bytepad(prefix, rate))
	return sh
}

// cshake128 returns `output_len` bytes of the cSHAKE128 output of `data` using
// function-name string `n` and customization string `s`.
pub fn cshake128(data []u8, output_len int, n []u8, s []u8) []u8 {
	mut sh := new_cshake128(n, s)
	sh.write(data)
	return sh.read(output_len)
}

// cshake256 returns `output_len` bytes of the cSHAKE256 output of `data` using
// function-name string `n` and customization string `s`.
pub fn cshake256(data []u8, output_len int, n []u8, s []u8) []u8 {
	mut sh := new_cshake256(n, s)
	sh.write(data)
	return sh.read(output_len)
}
