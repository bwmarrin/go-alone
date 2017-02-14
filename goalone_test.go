package goalone

import (
	"crypto/subtle"
	"encoding/hex"
	"testing"
)

func TestNewSecret(t *testing.T) {

	secret := []byte(`B1nzyRateLimits`)
	s := New(secret)
	if s == nil {
		t.Fatal("New returned a nil")
	}

	if s.hash == nil {
		t.Fatal("New returned a Sword with a nil hash")
	}

	if s.dirty {
		t.Fatal("New returned a dirty hash")
	}
}

func TestNewNil(t *testing.T) {

	s := New(nil)
	if s == nil {
		t.Fatal("New returned a nil")
	}

	if s.hash != nil {
		t.Fatal("New returned a Sword without nil hash")
	}

	if s.dirty {
		t.Fatal("New returned a dirty hash")
	}
}

func TestSign(t *testing.T) {

	secret := []byte(`B1nzyRateLimits`)
	data := []byte(`1203981209381290.LutinRocks`)
	want := []byte("1203981209381290.LutinRocks.")
	bs, _ := hex.DecodeString(`f728435d085e56b9345be75c0c09d6d3f0e094a9`)
	want = append(want, bs...)

	s := New(secret)
	token := s.Sign(data)

	if subtle.ConstantTimeCompare(token, want) != 1 {
		t.Logf("data: \n%x\n", data)
		t.Logf("want: \n%x\n", want)
		t.Logf("got : \n%x\n", token)
		t.Fatal("token and want do not match")
	}

	// sign after a dirty hash

	if !s.dirty {
		t.Fatal("Hash is not dirty, but it should be")
	}

	token = s.Sign(data)

	if subtle.ConstantTimeCompare(token, want) != 1 {
		t.Logf("data: \n%x\n", data)
		t.Logf("want: \n%x\n", want)
		t.Logf("got : \n%x\n", token)
		t.Fatal("token and want do not match")
	}

}

func TestUnsignTooLittle(t *testing.T) {

	secret := []byte(`B1nzyRateLimits`)
	token, _ := hex.DecodeString(`3132`)

	s := New(secret)
	ok, got := s.Unsign(token)

	if got != nil {
		t.Error("Unsign returned data, but should have returned nil")
	}

	if ok {
		t.Fatal("created token validated, but shouldn't have")
	}

}

func TestUnsign(t *testing.T) {

	secret := []byte(`B1nzyRateLimits`)
	token, _ := hex.DecodeString(`313230333938313230393338313239302e4c7574696e526f636b732ef728435d085e56b9345be75c0c09d6d3f0e094a9`)
	want := []byte(`1203981209381290.LutinRocks`)

	s := New(secret)
	ok, got := s.Unsign(token)
	if !ok {
		t.Fatal("created token did not validate")
	}
	if subtle.ConstantTimeCompare(got, want) != 1 {
		t.Logf("token: \n%x\n", token)
		t.Logf("want: \n%x\n", want)
		t.Logf("got : \n%x\n", got)
		t.Fatal("data of token does not match original data")
	}

	if !s.dirty {
		t.Fatal("Hash is not dirty, but it should be")
	}

	token, _ = hex.DecodeString(`313230333938313230393338313239302e4c7574696e526f636b732ef728435d085e56b9345be75c0c09d6d3f0e094a8`)
	ok, got = s.Unsign(token)
	if ok {
		t.Fatal("Invalid token was validated")
	}
	if got != nil {
		t.Logf("token: \n%x\n", token)
		t.Logf("want: nil\n")
		t.Logf("got : \n%x\n", got)
		t.Fatal("got should be nil")
	}
}

func BenchmarkSignLittle(b *testing.B) {
	secret := []byte(`B1nzyRateLimits`)
	data := []byte(`1203981209381290.LutinRocks`)

	b.ReportAllocs()
	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		New(secret).Sign(data)
	}
}

func BenchmarkReuseSignLittle(b *testing.B) {
	s := New([]byte(`B1nzyRateLimits`))
	data := []byte(`1203981209381290.LutinRocks`)

	b.ReportAllocs()
	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		s.Sign(data)
	}
}

func BenchmarkSignBig(b *testing.B) {
	secret := []byte(`B1nzyRateLimits`)
	data := []byte(`1203981209381290.7h90g7h089234g75908347gh09384h7v0897fg08947f5097423058974h908fg702f9j75028fg5704239hg7053498dj7249038jd57j097g5v029dh79hc47f507v9082h7f509234j7dc02d750j24935h7f924`)

	b.ReportAllocs()
	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		New(secret).Sign(data)
	}
}

func BenchmarkSignBigReuse(b *testing.B) {
	s := New([]byte(`B1nzyRateLimits`))
	data := []byte(`1203981209381290.7h90g7h089234g75908347gh09384h7v0897fg08947f5097423058974h908fg702f9j75028fg5704239hg7053498dj7249038jd57j097g5v029dh79hc47f507v9082h7f509234j7dc02d750j24935h7f924`)

	b.ReportAllocs()
	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		s.Sign(data)
	}
}

func BenchmarkUnsignLittle(b *testing.B) {
	secret := []byte(`B1nzyRateLimits`)
	data := []byte(`1203981209381290.LutinRocks`)

	s := New([]byte(`B1nzyRateLimits`))
	t := s.Sign(data)

	b.ReportAllocs()
	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		New(secret).Unsign(t)
	}
}

func BenchmarkUnsignLittleReuse(b *testing.B) {
	s := New([]byte(`B1nzyRateLimits`))
	data := []byte(`1203981209381290.LutinRocks`)
	t := s.Sign(data)

	b.ReportAllocs()
	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		s.Unsign(t)
	}
}

func BenchmarkUnsignBig(b *testing.B) {
	secret := []byte(`B1nzyRateLimits`)
	data := []byte(`1203981209381290.7h90g7h089234g75908347gh09384h7v0897fg08947f5097423058974h908fg702f9j75028fg5704239hg7053498dj7249038jd57j097g5v029dh79hc47f507v9082h7f509234j7dc02d750j24935h7f924`)
	s := New([]byte(`B1nzyRateLimits`))
	t := s.Sign(data)

	b.ReportAllocs()
	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		New(secret).Unsign(t)
	}
}

func BenchmarkSignerReuseValidateBig(b *testing.B) {
	s := New([]byte(`B1nzyRateLimits`))
	data := []byte(`1203981209381290.7h90g7h089234g75908347gh09384h7v0897fg08947f5097423058974h908fg702f9j75028fg5704239hg7053498dj7249038jd57j097g5v029dh79hc47f507v9082h7f509234j7dc02d750j24935h7f924`)
	t := s.Sign(data)

	b.ReportAllocs()
	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		s.Unsign(t)
	}
}
