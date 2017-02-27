package main

import (
	"time"

	"github.com/bwmarrin/go-alone"
)

func main() {

	// This secret is used as the hash key for the signer.
	var secret = []byte("It's a secret to everybody")

	// This data is what we will be signing below.
	var data = []byte("It's dangerous to go alone! Take this.")

	// Create a new Signer using our secret
	s := goalone.New(secret, nil)

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
	token3 := goalone.New(secret, nil).Sign(data)

	// Of course, you can Unsign with a one-liner too.
	data3, err3 := goalone.New(secret, nil).Unsign(token3)
	if err3 != nil {
		// signature is not valid
	} else {
		// signature is valid, it is safe to use the data
		println(string(data3))
	}

	// You can pass options to your new signer with the Options{} struct
	o := new(goalone.Options)

	// You can have the signer add timestamp to each token like this
	o.Timestamp = true

	// You can even set a custom timestamp epoch, if you want. Just give it a
	// unix timestamp in seconds and go-alone will use it as an offset for all
	// timestamps. This will allow you to better future proof your tokens or to
	// just make them more obsecure.
	o.Epoch = 1293840000

	// Now lets pass these options to our new signer then sign our data
	s = goalone.New(secret, o)
	token = s.Sign(data)

	// Of course you can do this all as a one liner too, but it does start to get
	// a bit too long :)
	token = goalone.New(secret, &goalone.Options{Timestamp: true, Epoch: 1293840000}).Sign(data)

	// You can parse out a token into a struct that separates the payload and
	// timestamp for you.
	ts := s.Parse(token)

	// Now, we can print the payload with
	println(string(ts.Payload))

	// We can print the timestamp with
	println(ts.Timestamp.String())

	// We can even check how old our timestamp is.  You can do a lot of other
	// things with the Timestamp too, since it's a standard time.Time value.
	if time.Since(ts.Timestamp) > time.Hour {
		// That token's timestamp is over an hour old!
	}

}
