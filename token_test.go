package goalone

import (
	"crypto/subtle"
	"testing"
)

func TestParse(t *testing.T) {

	secret := []byte(`B1nzyRateLimits`)
	want := []byte(`1203981209381290.LutinRocks`)
	bt := []byte(`1203981209381290.LutinRocks.9yhDXQheVrk0W-dcDAnW0_DglKk`)

	s := New(secret, nil)
	token := s.Parse(bt)

	if subtle.ConstantTimeCompare(token.Payload, want) != 1 {
		t.Logf("Got  %s\n", token.Payload)
		t.Logf("Want %s\n", want)
		t.Fatal("token and want do not match")
	}

	if !token.Timestamp.IsZero() {
		t.Fatal("Timestamp parsed incorrectly")
	}
}

func TestParseTimestamp(t *testing.T) {

	secret := []byte(`B1nzyRateLimits`)
	bt := []byte(`1203981209381290.LutinRocks.3gteYe.jeVOTSaWET1CPYeBRd_bLTwLYFw`)
	want := []byte(`1203981209381290.LutinRocks`)

	s := New(secret, &Options{Timestamp: true})
	token := s.Parse(bt)

	if subtle.ConstantTimeCompare(token.Payload, want) != 1 {
		t.Logf("Got  %s\n", token.Payload)
		t.Logf("Want %s\n", want)
		t.Fatal("token and want do not match")
	}

	if token.Timestamp.Unix() != 1487775993 {
		t.Logf("Got  %d\n", token.Timestamp.Unix())
		t.Logf("Want %s\n", want)
		t.Fatal("Timestamp parsed incorrectly")
	}
}

func BenchmarkParse(b *testing.B) {

	bt := []byte(`1203981209381290.LutinRocks.9yhDXQheVrk0W-dcDAnW0_DglKk`)
	secret := []byte(`B1nzyRateLimits`)
	s := New(secret, nil)

	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		s.Parse(bt)
	}
}

func BenchmarkParseTimestamp(b *testing.B) {

	bt := []byte(`1203981209381290.LutinRocks.3gteYe.jeVOTSaWET1CPYeBRd_bLTwLYFw`)
	secret := []byte(`B1nzyRateLimits`)
	s := New(secret, &Options{Timestamp: true})

	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		s.Parse(bt)
	}
}
