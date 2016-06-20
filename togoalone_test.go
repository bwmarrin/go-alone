package togoalone

import (
	"crypto/subtle"
	"testing"
)

func TestSigner(t *testing.T) {

	secret := []byte(`B1nzyRateLimits`)
	data := []byte(`1203981209381290.LutinRocks`)
	//	want := []byte{49, 50, 48, 51, 57, 56, 49, 50, 48, 57, 51, 56, 49, 50, 57, 48, 46, 76, 117, 116, 105, 110, 82, 111, 99, 107, 115, 46, 133, 212, 63, 127, 205, 94, 15, 192, 120, 198, 224, 171, 6, 110, 147, 101, 226, 74, 125, 5, 79, 155, 239, 75, 154, 29, 143, 53, 197, 242, 146, 43}

	signer := New(secret)
	token := signer.Sign(data)
	token2 := signer.Sign(data)

	if subtle.ConstantTimeCompare(token, token2) != 1 {
		t.Fatal("token and token2 do not match")
	}

	ok := signer.Validate(token)
	if !ok {
		t.Fatal("created token did not validate")
	}
}

func TestEncodeUint64(t *testing.T) {
	b1 := []byte{102, 95, 95, 95, 95, 95, 95, 95, 95, 95, 56}
	b2 := []byte{95, 95, 95, 95, 95, 95, 95, 95, 95, 95, 56}
	var i1 uint64 = 9223372036854775807
	var i2 uint64 = 0xFFFFFFFFFFFFFFFF

	if subtle.ConstantTimeCompare(b1, EncodeUint64(i1)) != 1 {
		t.Fatal("EncodeUint64 returned bad value for i1")
	}

	if subtle.ConstantTimeCompare(b2, EncodeUint64(i2)) != 1 {
		t.Fatal("EncodeUint64 returned bad value for i2")
	}
}

func TestDecodeUint64(t *testing.T) {
	var i uint64 = 0x00000000FFFFFFFF
	b := EncodeUint64(i)
	if DecodeUint64(b) != i {
		t.Fatal("DecodeUint64 returned bad value for b1")
	}

	var i2 uint64 = 0xFFFFFFFFFFFFFFFF
	b2 := EncodeUint64(i2)
	if DecodeUint64(b2) != i2 {
		t.Fatal("DecodeUint64 returned bad value for b2")
	}
}

func BenchmarkEncodeUint64(b *testing.B) {

	var ui uint64 = 0xFFFFFFFFFFFFFFFF

	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		EncodeUint64(ui)
	}
}

func BenchmarkDecodeUint64(b *testing.B) {

	var i uint64 = 0x00000000FFFFFFFF
	ei := EncodeUint64(i)

	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		DecodeUint64(ei)
	}
}
func BenchmarkSignerSignLittle(b *testing.B) {
	secret := []byte(`B1nzyRateLimits`)
	data := []byte(`1203981209381290.LutinRocks`)

	b.ReportAllocs()
	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		signer := New(secret)
		_ = signer.Sign(data)
	}
}

func BenchmarkSignerReuseSignLittle(b *testing.B) {
	signer := New([]byte(`B1nzyRateLimits`))
	data := []byte(`1203981209381290.LutinRocks`)

	b.ReportAllocs()
	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		_ = signer.Sign(data)
	}
}

func BenchmarkSignerSignBig(b *testing.B) {
	secret := []byte(`B1nzyRateLimits`)
	data := []byte(`1203981209381290.7h90g7h089234g75908347gh09384h7v0897fg08947f5097423058974h908fg702f9j75028fg5704239hg7053498dj7249038jd57j097g5v029dh79hc47f507v9082h7f509234j7dc02d750j24935h7f924`)

	b.ReportAllocs()
	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		signer := New(secret)
		_ = signer.Sign(data)
	}
}

func BenchmarkSignerReuseSignBig(b *testing.B) {
	signer := New([]byte(`B1nzyRateLimits`))
	data := []byte(`1203981209381290.7h90g7h089234g75908347gh09384h7v0897fg08947f5097423058974h908fg702f9j75028fg5704239hg7053498dj7249038jd57j097g5v029dh79hc47f507v9082h7f509234j7dc02d750j24935h7f924`)

	b.ReportAllocs()
	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		_ = signer.Sign(data)
	}
}

func BenchmarkSignerValidateLittle(b *testing.B) {
	secret := []byte(`B1nzyRateLimits`)
	data := []byte(`1203981209381290.LutinRocks`)

	signer := New([]byte(`B1nzyRateLimits`))
	token := signer.Sign(data)

	b.ReportAllocs()
	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		signer := New(secret)
		_ = signer.Validate(token)
	}
}

func BenchmarkSignerReuseValidateLittle(b *testing.B) {
	signer := New([]byte(`B1nzyRateLimits`))
	data := []byte(`1203981209381290.LutinRocks`)
	token := signer.Sign(data)

	b.ReportAllocs()
	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		_ = signer.Validate(token)
	}
}

func BenchmarkSignerValidateBig(b *testing.B) {
	secret := []byte(`B1nzyRateLimits`)
	data := []byte(`1203981209381290.7h90g7h089234g75908347gh09384h7v0897fg08947f5097423058974h908fg702f9j75028fg5704239hg7053498dj7249038jd57j097g5v029dh79hc47f507v9082h7f509234j7dc02d750j24935h7f924`)
	signer := New([]byte(`B1nzyRateLimits`))
	token := signer.Sign(data)

	b.ReportAllocs()
	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		signer := New(secret)
		_ = signer.Validate(token)
	}
}

func BenchmarkSignerReuseValidateBig(b *testing.B) {
	signer := New([]byte(`B1nzyRateLimits`))
	data := []byte(`1203981209381290.7h90g7h089234g75908347gh09384h7v0897fg08947f5097423058974h908fg702f9j75028fg5704239hg7053498dj7249038jd57j097g5v029dh79hc47f507v9082h7f509234j7dc02d750j24935h7f924`)
	token := signer.Sign(data)

	b.ReportAllocs()
	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		_ = signer.Validate(token)
	}
}
