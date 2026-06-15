module sha3

import encoding.hex

fn hx(s string) []u8 {
	return hex.decode(s) or { panic(err) }
}

fn rng_bytes(n int) []u8 {
	mut b := []u8{len: n}
	for i in 0 .. n {
		b[i] = u8(i)
	}
	return b
}

const kmac_key = hex.decode('404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f') or {
	panic(err)
}
const kmac_custom = 'My Tagged Application'.bytes()

// NIST SP 800-185 KMAC example values
fn test_kmac128_sample1() {
	got := kmac128(kmac_key, hx('00010203'), []u8{}, 32)
	want := hx('e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f456ee14e')
	assert got == want
}

fn test_kmac128_sample2() {
	got := kmac128(kmac_key, hx('00010203'), kmac_custom, 32)
	want := hx('3b1fba963cd8b0b59e8c1a6d71888b7143651af8ba0a7070c0979e2811324aa5')
	assert got == want
}

fn test_kmac128_sample3() {
	got := kmac128(kmac_key, rng_bytes(200), kmac_custom, 32)
	want := hx('1f5b4e6cca02209e0dcb5ca635b89a15e271ecc760071dfd805faa38f9729230')
	assert got == want
}

fn test_kmac256_sample4() {
	got := kmac256(kmac_key, hx('00010203'), kmac_custom, 64)
	want :=
		hx('20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd')
	assert got == want
}

fn test_kmac256_sample5() {
	// empty customization, verified independently with OpenSSL 3.0 KMAC256
	got := kmac256(kmac_key, hx('00010203'), []u8{}, 64)
	want :=
		hx('2ebd1622de2de44174e3477206060d7f64489a639b7545649132317609fa214f4c8ac90630fb4c757fba074b15186fe452ae71b6a1e443bf54059e090c11ae20')
	assert got == want
}

fn test_kmac256_sample6() {
	got := kmac256(kmac_key, rng_bytes(200), kmac_custom, 64)
	want :=
		hx('b58618f71f92e1d56c1b8c55ddd7cd188b97b4ca4d99831eb2699a837da2e4d970fbacfde50033aea585f1a2708510c32d07880801bd182898fe476876fc8965')
	assert got == want
}

// NIST SP 800-185 KMACXOF example values
fn test_kmacxof128_sample4() {
	got := kmac128xof(kmac_key, hx('00010203'), []u8{}, 32)
	want := hx('cd83740bbd92ccc8cf032b1481a0f4460e7ca9dd12b08a0c4031178bacd6ec35')
	assert got == want
}

fn test_kmacxof128_sample5() {
	got := kmac128xof(kmac_key, hx('00010203'), kmac_custom, 32)
	want := hx('31a44527b4ed9f5c6101d11de6d26f0620aa5c341def41299657fe9df1a3b16c')
	assert got == want
}

fn test_kmacxof128_sample6() {
	got := kmac128xof(kmac_key, rng_bytes(200), kmac_custom, 32)
	want := hx('47026c7cd793084aa0283c253ef658490c0db61438b8326fe9bddf281b83ae0f')
	assert got == want
}

fn test_kmacxof256_sample7() {
	got := kmac256xof(kmac_key, hx('00010203'), kmac_custom, 64)
	want :=
		hx('1755133f1534752aad0748f2c706fb5c784512cab835cd15676b16c0c6647fa96faa7af634a0bf8ff6df39374fa00fad9a39e322a7c92065a64eb1fb0801eb2b')
	assert got == want
}

fn test_kmacxof256_sample8() {
	got := kmac256xof(kmac_key, rng_bytes(200), []u8{}, 64)
	want :=
		hx('ff7b171f1e8a2b24683eed37830ee797538ba8dc563f6da1e667391a75edc02ca633079f81ce12a25f45615ec89972031d18337331d24ceb8f8ca8e6a19fd98b')
	assert got == want
}

fn test_kmacxof256_sample9() {
	got := kmac256xof(kmac_key, rng_bytes(200), kmac_custom, 64)
	want :=
		hx('d5be731c954ed7732846bb59dbe3a8e30f83e77a4bff4459f2f1c2b4ecebb8ce67ba01c62e8ab8578d2d499bd1bb276768781190020a306a97de281dcc30305d')
	assert got == want
}

// streaming write must match the one-shot helper
fn test_kmac_streaming_matches_oneshot() {
	data := rng_bytes(200)
	expected := kmac256(kmac_key, data, kmac_custom, 64)

	mut k := new_kmac256(kmac_key, kmac_custom, 64)
	k.write(data[..30])
	k.write(data[30..120])
	k.write(data[120..])
	assert k.sum() == expected
}

// incremental XOF reads must match a single large read
fn test_kmacxof_incremental_read() {
	data := hx('00010203')

	mut k1 := new_kmac128xof(kmac_key, kmac_custom)
	k1.write(data)
	all_at_once := k1.read(200)

	mut k2 := new_kmac128xof(kmac_key, kmac_custom)
	k2.write(data)
	mut chunked := []u8{}
	chunked << k2.read(50)
	chunked << k2.read(80)
	chunked << k2.read(70)

	assert chunked == all_at_once
}
