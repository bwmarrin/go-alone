package authtoken

import "testing"
import "time"

func BenchmarkGenerate(b *testing.B) {

	data := []byte(`this is some data`)
	secret := []byte(`zerorocks`)
	expire := time.Now()

	b.ReportAllocs()

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		Generate(expire, data, secret)
	}
}
