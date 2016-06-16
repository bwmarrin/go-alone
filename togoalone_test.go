package togoalone

import (
	"reflect"
	"testing"
)

func TestSigner(t *testing.T) {

	secret := []byte(`B1nzyRateLimits`)
	data := []byte(`1203981209381290.LutinRocks`)
	want := []byte{49, 50, 48, 51, 57, 56, 49, 50, 48, 57, 51, 56, 49, 50, 57, 48, 46, 76, 117, 116, 105, 110, 82, 111, 99, 107, 115, 46, 133, 212, 63, 127, 205, 94, 15, 192, 120, 198, 224, 171, 6, 110, 147, 101, 226, 74, 125, 5, 79, 155, 239, 75, 154, 29, 143, 53, 197, 242, 146, 43}

	signer := New(secret)
	token := signer.Sign(data)
	token2 := signer.Sign(data)

	if !reflect.DeepEqual(want, token) {
		t.Fatal("created token is not valid")
	}

	if !reflect.DeepEqual(want, token) {
		t.Fatal("created token2 is not valid")
	}

	if !reflect.DeepEqual(token, token2) {
		t.Fatal("token and token2 do not match")
	}

	ok := signer.Verify(token)
	if !ok {
		t.Fatal("created token did not verify")
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

func BenchmarkSignerVerifyLittle(b *testing.B) {
	secret := []byte(`B1nzyRateLimits`)
	data := []byte(`1203981209381290.LutinRocks`)

	signer := New([]byte(`B1nzyRateLimits`))
	token := signer.Sign(data)

	b.ReportAllocs()
	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		signer := New(secret)
		_ = signer.Verify(token)
	}
}

func BenchmarkSignerReuseVerifyLittle(b *testing.B) {
	signer := New([]byte(`B1nzyRateLimits`))
	data := []byte(`1203981209381290.LutinRocks`)
	token := signer.Sign(data)

	b.ReportAllocs()
	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		_ = signer.Verify(token)
	}
}

func BenchmarkSignerVerifyBig(b *testing.B) {
	secret := []byte(`B1nzyRateLimits`)
	data := []byte(`1203981209381290.7h90g7h089234g75908347gh09384h7v0897fg08947f5097423058974h908fg702f9j75028fg5704239hg7053498dj7249038jd57j097g5v029dh79hc47f507v9082h7f509234j7dc02d750j24935h7f924`)
	signer := New([]byte(`B1nzyRateLimits`))
	token := signer.Sign(data)

	b.ReportAllocs()
	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		signer := New(secret)
		_ = signer.Verify(token)
	}
}

func BenchmarkSignerReuseVerifyBig(b *testing.B) {
	signer := New([]byte(`B1nzyRateLimits`))
	data := []byte(`1203981209381290.7h90g7h089234g75908347gh09384h7v0897fg08947f5097423058974h908fg702f9j75028fg5704239hg7053498dj7249038jd57j097g5v029dh79hc47f507v9082h7f509234j7dc02d750j24935h7f924`)
	token := signer.Sign(data)

	b.ReportAllocs()
	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		_ = signer.Verify(token)
	}
}
