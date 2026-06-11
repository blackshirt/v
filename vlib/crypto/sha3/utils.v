module sha3

import math.bits
import encoding.binary

const cshake_rate128 = 168 // rate256
const cshake_rate256 = 136

// A costumizable SHAKE (cSHAKE) implementation.
@[noinit]
struct CShake {
mut:
	d         Digest
	initblock []u8
}

/*
fn new_cshake128(n []u8, s []u8) !&CShake {
	return new_cshake(n, s, cshake_rate128)!
}

fn new_cshake256(n []u8, s []u8) !&CShake {
	return new_cshake(n, s, cshake_rate256)!
}

fn new_cshake(n []u8, s []u8, absorption_rate int, hash_size int) !&CShake {
	if absorption_rate !in [cshake_rate128, cshake_rate256] {
		return error('unsupported cshake absorption_rate: ${rate}')
	}
	mut d := new_digest_unchecked(absorption_rate, hash_size, .cshake)
	// left_encode returns max 9 bytes
	mut initblock = []{len: 9*2+n.len(n)+s.len)
	initblock << left_encode(u64(n.len*8)))
	initblock << n
	initblock << left_encode(u64(s.len*8)))
	initblock << s
	d.write(bytepad(initblock, absorption_rate))
	cs := &CShake{
		d: d
		initialized: true
		n:           n
		s:           s
		initblock:   initblock
	}
	return cs
}
*/

// cSHAKE (cSHAKE128 and cSHAKE256)
//
// Both cSHAKE fntions take four parameters:
// • X is the main input bit string. It may be of any length3
// , including zero.
// • L is an integer representing the requested output length4 in bits.
// • N is a function-name bit string, used by NIST to define fntions based on cSHAKE.
// When no function other than cSHAKE is desired, N is set to the empty string.
// • S is a customization bit string. The user selects this string to define a variant of the
// function. When no customization is desired, S is set to the empty string5

// cSHAKE129
// cSHAKE128(X, L, N, S):
// Validity Conditions: n.len< 22040 and s.len< 22040
// 1. If N = "" and S = "":
// return SHAKE128(X, L);
// 2. Else:
// return KECCAK[256](bytepad(encode_string(N) || encode_string(S), 168) || X || 00, L).

fn cshake128(x []u8, length int, name []u8, s []u8) ![]u8 {
	if name.len == 0 && s.len == 0 {
		return shake128(x, length)
	}
	ecn := encode_string(name)
	ecs := encode_string(s)
	mut encoded := []u8{cap: ecn.len + ecs.len}
	encoded << ecn
	encoded << ecs

	mut data := []u8{cap: 9 + x.len + cshake_rate128 + 1}
	// xof_rate_128
	padded := bytepad(encoded, cshake_rate128)
	data << padded
	data << x
	data << u8(0x00)

	mut d := new_digest_unchecked(cshake_rate128, length, .cshake)
	// KECCAK[256](bytepad(encode_string(N) || encode_string(S), 168) || X || 00, L).
	d.write(data)!
	return d.checksum()
}

// right_encode(x) encodes the integer x as a byte string in a way that can be unambiguously parsed
// from the end of the string by inserting the length of the byte string after the byte string
// representation of x.
@[inline]
fn right_encode(x u64) []u8 {
	// Let n be the smallest positive integer for which 2⁸ⁿ > x
	mut n := (bits.len_64(x) + 7) / 8
	if n == 0 { n = 1 }
	// 2. Let x₁, x₂,…, xn be the base-256 encoding of x satisfying:
	// 		x = ∑ ²⁸⁽ⁿ⁻ⁱ⁾xᵢ, for i = 1 to n.
	// 3. Let Oi = enc₈(xi), for i = 1 to n.
	mut o := []u8{len: 9}
	binary.big_endian_put_u64(mut o, x)
	o = unsafe { o[9 - n - 1..] }
	// 4. Let On+1 = enc₈(n).
	o[n] = u8(n)
	// 5. Return O = O1 || O2 || … || On || On+1.
	// o = x || n with n as a byte and x an n bytes in big-endian.
	return o
}

// left_encode(x) encodes the integer x as a byte string in a way that can be unambiguously parsed
// from the beginning of the string by inserting the length of the byte string before the byte string
// representation of x
@[inline]
fn left_encode(x u64) []u8 {
	// 1. Let n be the smallest positive integer for which 2⁸ⁿ > x
	mut n := (bits.len_64(x) + 7) / 8
	if n == 0 { n = 1 }
	// 2. Let x₁, x₂,…, xn be the base-256 encoding of x satisfying:
	// 		x = ∑ ²⁸⁽ⁿ⁻ⁱ⁾xᵢ, for i = 1 to n.
	// 3. Let Oi = enc₈(xi), for i = 1 to n.
	mut o := []u8{len: 9}
	binary.big_endian_put_u64(mut o[1..], x)
	o = unsafe { o[9 - n - 1..] }
	// 4. Let O0 = enc₈(n).
	o[0] = u8(n)
	// 5. Return O = O0 || O1 || … || On−1 || On.
	// Return n || x with n as a byte and x an n bytes in big-endian order.
	return o
}

// encode_string function is used to encode bit strings in a way that may be parsed
// unambiguously from the beginning of the string
@[direct_array_access; inline]
fn encode_string(s []u8) []u8 {
	// Return left_encode(s.len) || S.
	les := left_encode(u64(s.len))
	mut out := []u8{cap: les.len + s.len}
	out << les
	out << s
	return s
}

// bytepad(X, w) prepends an encoding of the integer w to an input string X, then pads
// the result with zeros until it is a byte string whose length in bytes is a multiple of w
// w > 0
fn bytepad(x []u8, w int) []u8 {
	mut z := []u8{cap: 9 + x.len + w + 1}
	// 1. z = left_encode(w) || X.
	z << left_encode(u64(w))
	z << x
	// 2. while len(z) mod 8 ≠ 0:
	// z = z || 0
	// 3. while (len(z)/8) mod w ≠ 0:
	// z = z || 00000000
	padlen := w - z.len % w
	if padlen < w {
		pad := []u8{len: padlen}
		z << pad
	}
	// 4. return z.
	return z
}
