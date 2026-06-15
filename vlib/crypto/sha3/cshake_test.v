module sha3

import encoding.hex

fn hx(s string) []u8 {
	return hex.decode(s) or { panic(err) }
}

// rng_bytes returns n bytes with the values 0x00, 0x01, ... 0xff, 0x00, ...
// matching the data used by the NIST SP 800-185 example values.
fn rng_bytes(n int) []u8 {
	mut b := []u8{len: n}
	for i in 0 .. n {
		b[i] = u8(i)
	}
	return b
}

// encoding helpers (NIST SP 800-185 sec 2.3)
fn test_left_encode() {
	assert left_encode(0) == [u8(1), 0]
	assert left_encode(1) == [u8(1), 1]
	assert left_encode(255) == [u8(1), 255]
	assert left_encode(256) == [u8(2), 1, 0]
	assert left_encode(65536) == [u8(3), 1, 0, 0]
}

fn test_right_encode() {
	assert right_encode(0) == [u8(0), 1]
	assert right_encode(1) == [u8(1), 1]
	assert right_encode(255) == [u8(255), 1]
	assert right_encode(256) == [u8(1), 0, 2]
}

fn test_encode_string() {
	// empty string encodes its bit length 0
	assert encode_string([]u8{}) == [u8(1), 0]
	// "abc" -> left_encode(24) || 'abc'
	assert encode_string('abc'.bytes()) == [u8(1), 24, u8(`a`), u8(`b`), u8(`c`)]
}

fn test_bytepad() {
	// bytepad of empty input with w=4 -> left_encode(4) padded to length 4
	assert bytepad([]u8{}, 4) == [u8(1), 4, 0, 0]
	out := bytepad('abc'.bytes(), 4)
	assert out.len % 4 == 0
	assert out[..2] == [u8(1), 4]
}

// NIST SP 800-185 cSHAKE example values
fn test_cshake128_sample1() {
	got := cshake128(hx('00010203'), 32, []u8{}, 'Email Signature'.bytes())
	want := hx('c1c36925b6409a04f1b504fcbca9d82b4017277cb5ed2b2065fc1d3814d5aaf5')
	assert got == want
}

fn test_cshake128_sample2() {
	got := cshake128(rng_bytes(200), 32, []u8{}, 'Email Signature'.bytes())
	want := hx('c5221d50e4f822d96a2e8881a961420f294b7b24fe3d2094baed2c6524cc166b')
	assert got == want
}

fn test_cshake256_sample3() {
	got := cshake256(hx('00010203'), 64, []u8{}, 'Email Signature'.bytes())
	want :=
		hx('d008828e2b80ac9d2218ffee1d070c48b8e4c87bff32c9699d5b6896eee0edd164020e2be0560858d9c00c037e34a96937c561a74c412bb4c746469527281c8c')
	assert got == want
}

fn test_cshake256_sample4() {
	got := cshake256(rng_bytes(200), 64, []u8{}, 'Email Signature'.bytes())
	want :=
		hx('07dc27b11e51fbac75bc7b3c1d983e8b4b85fb1defaf218912ac86430273091727f42b17ed1df63e8ec118f04b23633c1dfb1574c8fb55cb45da8e25afb092bb')
	assert got == want
}

// cSHAKE with empty function-name and customization is plain SHAKE
fn test_cshake_empty_is_shake() {
	data := 'the quick brown fox'.bytes()
	assert cshake128(data, 32, []u8{}, []u8{}) == shake128(data, 32)
	assert cshake256(data, 64, []u8{}, []u8{}) == shake256(data, 64)
}

fn test_cshake_streaming_matches_oneshot() {
	data := rng_bytes(200)
	custom := 'Email Signature'.bytes()
	expected := cshake256(data, 64, []u8{}, custom)

	mut s := new_cshake256([]u8{}, custom)
	s.write(data[..50])
	s.write(data[50..])
	assert s.read(64) == expected
}
