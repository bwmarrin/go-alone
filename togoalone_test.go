package togoalone

import "testing"

func BenchmarkSignerSignLittle(b *testing.B) {

	b.ReportAllocs()

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		Signer([]byte(`B1nzyRateLimits`)).Sign([]byte(`1203981209381290.LutinRocks`))
	}
}

func BenchmarkSignerReuseSignLittle(b *testing.B) {

	s := Signer([]byte(`B1nzyRateLimits`))

	b.ReportAllocs()

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		s.Sign([]byte(`1203981209381290.LutinRocks`))
	}
}
func BenchmarkSignerSignBig(b *testing.B) {

	b.ReportAllocs()

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		Signer([]byte(`B1nzyRateLimits`)).Sign([]byte(`1203981209381290.7h90g7h089234g75908347gh09384h7v0897fg08947f5097423058974h908fg702f9j75028fg5704239hg7053498dj7249038jd57j097g5v029dh79hc47f507v9082h7f509234j7dc02d750j24935h7f924`))
	}
}

func BenchmarkSignerReuseSignBig(b *testing.B) {

	s := Signer([]byte(`B1nzyRateLimits`))

	b.ReportAllocs()

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		s.Sign([]byte(`1203981209381290.7h90g7h089234g75908347gh09384h7v0897fg08947f5097423058974h908fg702f9j75028fg5704239hg7053498dj7249038jd57j097g5v029dh79hc47f507v9082h7f509234j7dc02d750j24935h7f924`))
	}
}
