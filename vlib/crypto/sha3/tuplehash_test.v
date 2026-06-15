module sha3

import encoding.hex

fn hx(s string) []u8 {
	return hex.decode(s) or { panic(err) }
}

const th_tuple2 = [hx('000102'), hx('101112131415')]
const th_tuple3 = [hx('000102'), hx('101112131415'), hx('202122232425262728')]
const th_custom = 'My Tuple App'.bytes()

// NIST SP 800-185 TupleHash example values
fn test_tuplehash128_sample1() {
	got := tuplehash128(th_tuple2, []u8{}, 32)
	want := hx('c5d8786c1afb9b82111ab34b65b2c0048fa64e6d48e263264ce1707d3ffc8ed1')
	assert got == want
}

fn test_tuplehash128_sample2() {
	got := tuplehash128(th_tuple2, th_custom, 32)
	want := hx('75cdb20ff4db1154e841d758e24160c54bae86eb8c13e7f5f40eb35588e96dfb')
	assert got == want
}

fn test_tuplehash128_sample3() {
	got := tuplehash128(th_tuple3, th_custom, 32)
	want := hx('e60f202c89a2631eda8d4c588ca5fd07f39e5151998deccf973adb3804bb6e84')
	assert got == want
}

fn test_tuplehash256_sample4() {
	got := tuplehash256(th_tuple2, []u8{}, 64)
	want :=
		hx('cfb7058caca5e668f81a12a20a2195ce97a925f1dba3e7449a56f82201ec607311ac2696b1ab5ea2352df1423bde7bd4bb78c9aed1a853c78672f9eb23bbe194')
	assert got == want
}

fn test_tuplehash256_sample5() {
	got := tuplehash256(th_tuple2, th_custom, 64)
	want :=
		hx('147c2191d5ed7efd98dbd96d7ab5a11692576f5fe2a5065f3e33de6bba9f3aa1c4e9a068a289c61c95aab30aee1e410b0b607de3620e24a4e3bf9852a1d4367e')
	assert got == want
}

fn test_tuplehash256_sample6() {
	got := tuplehash256(th_tuple3, th_custom, 64)
	want :=
		hx('45000be63f9b6bfd89f54717670f69a9bc763591a4f05c50d68891a744bcc6e7d6d5b5e82c018da999ed35b0bb49c9678e526abd8e85c13ed254021db9e790ce')
	assert got == want
}

// NIST SP 800-185 TupleHashXOF example values
fn test_tuplehashxof128_sample1() {
	got := tuplehash128xof(th_tuple2, []u8{}, 32)
	want := hx('2f103cd7c32320353495c68de1a8129245c6325f6f2a3d608d92179c96e68488')
	assert got == want
}

fn test_tuplehashxof128_sample2() {
	got := tuplehash128xof(th_tuple2, th_custom, 32)
	want := hx('3fc8ad69453128292859a18b6c67d7ad85f01b32815e22ce839c49ec374e9b9a')
	assert got == want
}

fn test_tuplehashxof256_sample4() {
	got := tuplehash256xof(th_tuple2, []u8{}, 64)
	want :=
		hx('03ded4610ed6450a1e3f8bc44951d14fbc384ab0efe57b000df6b6df5aae7cd568e77377daf13f37ec75cf5fc598b6841d51dd207c991cd45d210ba60ac52eb9')
	assert got == want
}

// the tuple boundaries must matter: ("abc","d") != ("ab","cd")
fn test_tuplehash_boundaries_matter() {
	a := tuplehash128(['abc'.bytes(), 'd'.bytes()], []u8{}, 32)
	b := tuplehash128(['ab'.bytes(), 'cd'.bytes()], []u8{}, 32)
	assert a != b
}

// streaming element-by-element must match the one-shot helper
fn test_tuplehash_streaming_matches_oneshot() {
	expected := tuplehash256(th_tuple3, th_custom, 64)

	mut t := new_tuplehash256(th_custom, 64)
	for element in th_tuple3 {
		t.write(element)
	}
	assert t.sum() == expected
}
