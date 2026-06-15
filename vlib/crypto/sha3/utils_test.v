module sha3

const myfn = 'myfunction_name'.bytes()
const mycs = 'mycustom_string'.bytes()
const mymsg = 'my message data'.bytes()

struct CShakeTest {
	length int
	exp    string
}

// with fixed n, s, and message
const cshake_test_data = [
	CShakeTest{4, '7dfcfa65'},
	CShakeTest{32, '7dfcfa659c4f806b5e35e7f5416cd88eed105d027060a12ddf0df09882a4f042'},
	CShakeTest{64, '7dfcfa659c4f806b5e35e7f5416cd88eed105d027060a12ddf0df09882a4f042dcef78095d2e54a14f9d973a2db3ca397e39ff2f30c2b125bcbf8c4432124c1d'},
]

fn test_cshake_hash() ! {
	for o in cshake_test_data {
		mut s := new_cshake128(myfn, mycs)!
		s.write(mymsg)
		out := s.read(o.length)
		assert out.hex() == o.exp
	}
}

fn test_cshake_128() ! {
	n := 'name'.bytes()
	length := 32
	s := 'custom'.bytes()
	x := 'message'.bytes()

	exp := 'd027ee43389621c5fe3787ee6bb3e60c0c2a53d3dcb9e166c0580a6cfa9aa96b'
	mut c := new_cshake128(n, s)!
	c.write(x)
	out := c.read(length)
	assert out.hex() == exp
}

fn test_left_encode() ! {
	// https://go.dev/play/p/3Oc-qDxmsBV
	//
	// Input key:     4096 | LeftEncode Output: 021000 (Expected: 021000)
	// Input key:    65535 | LeftEncode Output: 02ffff (Expected: 02ffff)
	// Input key:    65536 | LeftEncode Output: 03010000 (Expected: 03010000)
	// Input key: 18446744073709551615 | LeftEncode Output: 08ffffffffffffffff (Expected: 08ffffffffffffffff)
	// Input key:        0 | LeftEncode Output: 0100 (Expected: 0100)
	// Input key:      128 | LeftEncode Output: 0180 (Expected: 0180)
	// Input key:    54321 | LeftEncode Output: 02d431 (Expected: 02d431)
	// Input key: 1677721530 | LeftEncode Output: 0463ffffba (Expected: 0463ffffba)
	// Input key:      255 | LeftEncode Output: 01ff (Expected: 01ff)
	m := {
		u64(0):               [u8(0x01), 0x00]
		128:                  [u8(0x01), 128]
		255:                  [u8(0x01), 0xFF]
		4096:                 [u8(0x02), 16, 0]
		54321:                [u8(2), 212, 49]
		65535:                [u8(0x02), 0xFF, 0xFF]
		65536:                [u8(0x03), 1, 0, 0]
		1677721530:           [u8(4), 99, 0xFF, 0xFF, 186]
		18446744073709551615: [u8(8), 255, 255, 255, 255, 255, 255, 255, 255]
	}
	for k, v in m {
		out := left_encode(k)
		assert out == v
	}
}

fn test_cshake_empty_customization_matches_shake() ! {
	msg := 'abc'.bytes()
	assert cshake128(msg, 64, []u8{}, []u8{}) == shake128(msg, 64)
	assert cshake256(msg, 64, []u8{}, []u8{}) == shake256(msg, 64)
}

fn test_cshake_one_shot_matches_streaming() ! {
	msg := 'message'.bytes()
	name := 'name'.bytes()
	custom := 'custom'.bytes()
	mut h128 := new_cshake128(name, custom)!
	h128.write(msg[..3])
	h128.write(msg[3..])
	assert h128.read(64) == cshake128(msg, 64, name, custom)
	mut h256 := new_cshake256(name, custom)!
	h256.write(msg[..3])
	h256.write(msg[3..])
	assert h256.read(64) == cshake256(msg, 64, name, custom)
}

fn test_parallel_hash_errors() ! {
	if _ := parallel_hash128('abc'.bytes(), 32, 0, []u8{}) {
		assert false, 'parallel_hash128 should reject zero block size'
	} else {
		assert err.msg() == 'ParallelHash block size must be > 0'
	}
	if _ := parallel_hash256('abc'.bytes(), -1, 8, []u8{}) {
		assert false, 'parallel_hash256 should reject negative output length'
	} else {
		assert err.msg() == 'ParallelHash output length must be >= 0'
	}
}

fn test_parallel_hash_is_deterministic_and_customizable() ! {
	msg := 'ParallelHash input message'.bytes()
	a := parallel_hash128(msg, 32, 8, 'A'.bytes())!
	b := parallel_hash128(msg, 32, 8, 'A'.bytes())!
	c := parallel_hash128(msg, 32, 8, 'B'.bytes())!
	assert a == b
	assert a != c
	out := parallel_hash256(msg, 64, 8, 'A'.bytes())!
	assert out.len == 64
}
