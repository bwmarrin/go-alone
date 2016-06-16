package togoalone

import (
	"testing"
)

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
