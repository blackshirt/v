// Copyright (c) 2023 Kim Shrier. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

// streaming shake-128/256 xof per FIPS 202
// https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.202.pdf

module sha3

@[noinit]
pub struct Shake {
	rate   int // bytes per permutation (168 for shake-128, 136 for shake-256)
	suffix u8
mut:
	s            State
	input_buffer []u8
	finalized    bool
	squeeze_buf  []u8
}

// new_cshake128 returns a new cSHAKE128 instance customized with function name n and
// customization string s. When both n and s are empty, it returns SHAKE128.
pub fn new_cshake128(n []u8, s []u8) !&Shake {
	if n.len == 0 && s.len == 0 {
		return new_shake128()
	}
	return new_cshake(cshake_rate128, n, s)!
}

// new_cshake256 returns a new cSHAKE256 instance customized with function name n and
// customization string s. When both n and s are empty, it returns SHAKE256.
pub fn new_cshake256(n []u8, s []u8) !&Shake {
	if n.len == 0 && s.len == 0 {
		return new_shake256()
	}
	return new_cshake(cshake_rate256, n, s)!
}

fn new_cshake(rate int, n []u8, s []u8) !&Shake {
	if rate !in [cshake_rate128, cshake_rate256] {
		return error('unsupported cSHAKE absorption rate: ${rate}')
	}
	mut c := &Shake{
		rate:   rate
		suffix: u8(Padding.cshake)
	}
	mut initblock := []u8{cap: 9 + n.len + 9 + s.len}
	initblock << encode_string(n)
	initblock << encode_string(s)
	write_bytepad(mut c, initblock, c.rate)!
	return c
}

fn write_bytepad(mut c Shake, data []u8, rate int) ! {
	rate_encoded := left_encode(u64(rate))
	c.write(rate_encoded)
	c.write(data)
	padlen := rate - (rate_encoded.len + data.len) % rate
	if padlen < rate {
		padbytes := []u8{len: padlen, cap: cshake_rate128}
		c.write(padbytes)
	}
}

// new_shake128 returns a new Shake instance for SHAKE-128 extended output function.
pub fn new_shake128() &Shake {
	return &Shake{
		rate:   xof_rate_128
		suffix: u8(Padding.xof)
	}
}

// new_shake256 returns a new Shake instance for SHAKE-256 extended output function.
pub fn new_shake256() &Shake {
	return &Shake{
		rate:   xof_rate_256
		suffix: u8(Padding.xof)
	}
}

// write absorbs more data into the sponge state.
// Panics if called after `read`.
@[direct_array_access]
pub fn (mut s Shake) write(data []u8) {
	if s.finalized {
		panic('sha3: write after read on Shake')
	}
	if data.len == 0 {
		return
	}

	// avoid cloning on each iteration
	mut remaining := unsafe { data[..] }

	if s.input_buffer.len != 0 {
		empty_space := s.rate - s.input_buffer.len

		if remaining.len < empty_space {
			s.input_buffer << remaining
			return
		} else {
			s.input_buffer << remaining[..empty_space]
			remaining = unsafe { remaining[empty_space..] }

			s.s.xor_bytes(s.input_buffer[..s.rate], s.rate)
			s.s.kaccak_p_1600_24()

			s.input_buffer = []u8{}
		}
	}

	for remaining.len >= s.rate {
		s.s.xor_bytes(remaining[..s.rate], s.rate)
		s.s.kaccak_p_1600_24()
		remaining = unsafe { remaining[s.rate..] }
	}

	if remaining.len > 0 {
		s.input_buffer = remaining.clone()
	}
}

fn (mut s Shake) finalize() {
	if s.finalized {
		return
	}
	s.finalized = true

	// pad10*1 with xof domain separator 0x1f (FIPS 202 sec B.2)
	mut padded := s.input_buffer.clone()
	if padded.len == s.rate - 1 {
		padded << u8(0x80 | s.suffix)
	} else {
		padded << s.suffix
		for padded.len < s.rate - 1 {
			padded << u8(0x00)
		}
		padded << u8(0x80)
	}

	s.s.xor_bytes(padded[..s.rate], s.rate)
	s.s.kaccak_p_1600_24()

	state_bytes := s.s.to_bytes()
	s.squeeze_buf = state_bytes[..s.rate].clone()
	s.input_buffer = []u8{}
}

// read squeezes `out_len` bytes from the sponge state.
// Finalizes the sponge on first call; further calls to `write` will panic.
@[direct_array_access]
pub fn (mut s Shake) read(out_len int) []u8 {
	if !s.finalized {
		s.finalize()
	}

	mut result := []u8{cap: out_len}
	mut remaining := out_len

	for remaining > 0 {
		if s.squeeze_buf.len == 0 {
			s.s.kaccak_p_1600_24()
			state_bytes := s.s.to_bytes()
			s.squeeze_buf = state_bytes[..s.rate].clone()
		}

		take := if remaining < s.squeeze_buf.len { remaining } else { s.squeeze_buf.len }
		result << s.squeeze_buf[..take]
		s.squeeze_buf = s.squeeze_buf[take..].clone()
		remaining -= take
	}

	return result
}

// reset clears the sponge state, allowing the Shake instance to be reused.
pub fn (mut s Shake) reset() {
	s.s = State{}
	s.input_buffer = []u8{}
	s.finalized = false
	s.squeeze_buf = []u8{}
}
