package authtoken

import "fmt"
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

func TestGenerate(t *testing.T) {

	data := []byte(`this is some data`)
	secret := []byte(`zerorocks`)
	expire := time.Now()

	_, err := Generate(expire, data, secret)
	if err != nil {
		t.Fatal(err)
	}
}

func TestVerify(t *testing.T) {

	data := []byte(`this is some data`)
	secret := []byte(`zerorocks`)
	expire := time.Now().Add(1 * time.Hour)

	token, err := Generate(expire, data, secret)
	if err != nil {
		t.Fatal(err)
	}

	b, err := Verify(token.String(), secret)
	if err != nil {
		t.Fatal(err)
	}

	if !b {
		t.Fatal("token does not validate")
	}
}

func ExampleGenerate() {

	fmt.Println("Got here")

	data := []byte(`this is some data`)
	secret := []byte(`zerorocks`)
	expire := time.Now()

	token, err := Generate(expire, data, secret)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(token)
	// Output: wrong_answer_on_purpose
}
