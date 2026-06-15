module sha3

import math.bits
import encoding.binary

const cshake_rate128 = 168
const cshake_rate256 = 136

// cshake128 returns `output_len` bytes from cSHAKE128 for data, function name n,
// and customization string s.
pub fn cshake128(data []u8, output_len int, n []u8, s []u8) []u8 {
	mut h := new_cshake128(n, s) or { panic(err) }
	h.write(data)
	return h.read(output_len)
}

// cshake256 returns `output_len` bytes from cSHAKE256 for data, function name n,
// and customization string s.
pub fn cshake256(data []u8, output_len int, n []u8, s []u8) []u8 {
	mut h := new_cshake256(n, s) or { panic(err) }
	h.write(data)
	return h.read(output_len)
}

// parallel_hash128 returns `output_len` bytes from ParallelHash128 using block_size
// bytes per input chunk and customization string s.
pub fn parallel_hash128(data []u8, output_len int, block_size int, s []u8) ![]u8 {
	return parallel_hash(data, output_len, block_size, s, cshake_rate128, 32)!
}

// parallel_hash256 returns `output_len` bytes from ParallelHash256 using block_size
// bytes per input chunk and customization string s.
pub fn parallel_hash256(data []u8, output_len int, block_size int, s []u8) ![]u8 {
	return parallel_hash(data, output_len, block_size, s, cshake_rate256, 64)!
}

fn parallel_hash(
	data []u8,
	output_len int,
	block_size int,
	s []u8,
	rate int,
	chunk_output_len int,
) ![]u8 {
	if output_len < 0 {
		return error('ParallelHash output length must be >= 0')
	}
	if block_size <= 0 {
		return error('ParallelHash block size must be > 0')
	}
	mut encoded := []u8{cap: 9 + data.len + 18}
	encoded << left_encode(u64(block_size))
	mut chunk_count := 0
	for start := 0; start < data.len; start += block_size {
		end := int_min(start + block_size, data.len)
		chunk := unsafe { data[start..end] }
		if rate == cshake_rate128 {
			encoded << cshake128(chunk, chunk_output_len, []u8{}, []u8{})
		} else {
			encoded << cshake256(chunk, chunk_output_len, []u8{}, []u8{})
		}
		chunk_count++
	}
	encoded << right_encode(u64(chunk_count))
	encoded << right_encode(u64(output_len) << 3)
	if rate == cshake_rate128 {
		return cshake128(encoded, output_len, 'ParallelHash'.bytes(), s)
	}
	return cshake256(encoded, output_len, 'ParallelHash'.bytes(), s)
}

// right_encode encodes the integer x as a byte string in a way that can be unambiguously parsed
// from the end of the string by inserting the length of the byte string after the byte string
// representation of x.
@[inline]
fn right_encode(x u64) []u8 {
	mut n := (bits.len_64(x) + 7) / 8
	if n == 0 {
		n = 1
	}
	mut o := []u8{len: 9}
	binary.big_endian_put_u64(mut o, x)
	o = unsafe { o[9 - n - 1..] }
	o[n] = u8(n)
	return o
}

// left_encode encodes the integer x as a byte string in a way that can be unambiguously parsed
// from the beginning of the string by inserting the length of the byte string before
// the byte string representation of x.
@[inline]
fn left_encode(x u64) []u8 {
	mut n := (bits.len_64(x) + 7) / 8
	if n == 0 {
		n = 1
	}
	mut o := []u8{len: 9}
	binary.big_endian_put_u64(mut o[1..], x)
	o = unsafe { o[9 - n - 1..] }
	o[0] = u8(n)
	return o
}

// encode_string encodes a byte string as left_encode(len(s) * 8) || s.
@[direct_array_access; inline]
fn encode_string(s []u8) []u8 {
	les := left_encode(u64(s.len) << 3)
	mut out := []u8{cap: les.len + s.len}
	out << les
	out << s
	return out
}

// bytepad prepends left_encode(w) to x and pads with zeros to a multiple of w bytes.
fn bytepad(x []u8, w int) []u8 {
	mut z := []u8{cap: 9 + x.len + w}
	z << left_encode(u64(w))
	z << x
	padlen := w - z.len % w
	if padlen < w {
		z << []u8{len: padlen}
	}
	return z
}
