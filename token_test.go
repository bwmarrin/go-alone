package goalone

import (
	"crypto/subtle"
	"testing"
)

func TestParse(t *testing.T) {

	secret := []byte(`B1nzyRateLimits`)
	want := []byte(`1203981209381290.LutinRocks`)
	bt := []byte(`1203981209381290.LutinRocks.ZGRsRXvTb08ld7xmJImL1ykGr8D1JmrSPGc134nBNRo`)

	s := New(secret)
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
	bt := []byte(`1203981209381290.LutinRocks.3gteYe.ZGRsRXvTb08ld7xmJImL1ykGr8D1JmrSPGc134nBNRo`)
	want := []byte(`1203981209381290.LutinRocks`)

	s := New(secret, Timestamp)
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

	bt := []byte(`1203981209381290.LutinRocks.ZGRsRXvTb08ld7xmJImL1ykGr8D1JmrSPGc134nBNRo`)
	secret := []byte(`B1nzyRateLimits`)
	s := New(secret)

	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		s.Parse(bt)
	}
}

func BenchmarkParseTimestamp(b *testing.B) {

	bt := []byte(`1203981209381290.LutinRocks.3gteYe.ZGRsRXvTb08ld7xmJImL1ykGr8D1JmrSPGc134nBNRo`)
	secret := []byte(`B1nzyRateLimits`)
	s := New(secret, Timestamp)

	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		s.Parse(bt)
	}
}
