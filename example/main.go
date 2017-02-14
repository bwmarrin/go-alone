package main

import "github.com/bwmarrin/go-alone"

func main() {

	// This secret is used as the hash key for the signer.
	var secret = []byte("It's a secret to everybody")

	// This data is what we will be signing below.
	var data = []byte("It's dangerous to go alone! Take this.")

	// Create a new Signer using our secret
	s := goalone.New(secret)

	// Sign and return a token in the form of `data.signature`
	token := s.Sign(data)

	// You can reuse this struct as many times as you wish
	token2 := s.Sign(data)

	// You can easily Unsign a token, which will verify the signature is valid
	// then return signed data of the token.
	data, err := s.Unsign(token)
	if err != nil {
		// signature is not valid
	} else {
		// signature is valid, it is safe to use the data
		println(string(data))
	}

	// Of course, you can do this as many times as needed as well.
	data2, err2 := s.Unsign(token2)
	if err2 != nil {
		// signature is not valid
	} else {
		// signature is valid, it is safe to use the data
		println(string(data2))
	}

	// You can also write one-liners when you will not be reusing the hash.
	token3 := goalone.New(secret).Sign(data)

	// Of course, you can Unsign with a one-liner too.
	data3, err3 := goalone.New(secret).Unsign(token3)
	if err3 != nil {
		// signature is not valid
	} else {
		// signature is valid, it is safe to use the data
		println(string(data3))
	}
}
