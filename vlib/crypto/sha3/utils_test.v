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
