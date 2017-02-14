<img align="right" src="http://vignette1.wikia.nocookie.net/zelda/images/2/28/Hyrule_Warriors_Hylian_Sword_8-Bit_Wooden_Sword_(8-bit_Hylian_Sword).png">
It's dangerous to **go-alone**! Take this.

[![GoDoc](https://godoc.org/github.com/bwmarrin/go-alone?status.svg)](https://godoc.org/github.com/bwmarrin/go-alone) [![Go report](http://goreportcard.com/badge/bwmarrin/go-alone)](http://goreportcard.com/report/bwmarrin/go-alone) [![Build Status](https://travis-ci.org/bwmarrin/go-alone.svg?branch=master)](https://travis-ci.org/bwmarrin/go-alone) [![Coverage](http://gocover.io/_badge/github.com/bwmarrin/go-alone)](https://gocover.io/github.com/bwmarrin/go-alone) [![Discord Gophers](https://img.shields.io/badge/Discord%20Gophers-%23info-blue.svg)](https://discord.gg/0f1SbxBZjYq9jLBk)

**WARNING:** go-alone is in very early stages where I'm still hashing out how I
want to design the package.  You're free to use it but things will probably 
change.  I would be very interested in chatting with anyone with ideas on how
to best structure this library.

go-alone is a [Go](https://golang.org/) package that provides (or will) :
* A very simple to use HMAC token signer, unsigner, and verifier package.
* Compatibility with [itsdangerous](https://pythonhosted.org/itsdangerous/) tokens.

**For help with this package or general Go discussion, please join the [Discord 
Gophers](https://discord.gg/0f1SbxBZjYq9jLBk) chat server.**

## Getting Started

### Installing

This assumes you already have a working Go environment, if not please see
[this page](https://golang.org/doc/install) first.

```sh
go get github.com/bwmarrin/go-alone
```

### Usage

See the below example program.

```go
package main

import "github.com/bwmarrin/go-alone"

func main() {

	var secret = []byte("It's Dangerous to go alone! Take this.")
	var data = []byte("The right thing... what is it? I wonder, if you do the right thing, does it really make everyone happy?")

	//

	// Create a new Signer using our secret
	s := goalone.New(secret)

	// Sign and return a token in the form of `data.signature`
	token := s.Sign(data)

	// You can reuse this struct as many times as you wish
	token2 := s.Sign(data)

	// You can easily Unsign a token, which will verify the signature is valiod
	// then return signed data of the token.
	ok, data := s.Unsign(token)
	if !ok {
		// signature is not valid
	} else {
		// signature is valid, it is safe to use the data
		println(string(data))
	}

	// Of course, you can do this as many times as needed as well.
	ok2, data2 := s.Unsign(token2)
	if !ok2 {
		// signature is not valid
	} else {
		// signature is valid, it is safe to use the data
		println(string(data2))
	}

	// You can also write one-liners when you will not be reusing the hash.
	token3 := goalone.New(secret).Sign(data)

	// Of course, you can Unsign with a one-liner too.
	ok3, data3 := goalone.New(secret).Unsign(token3)
	if !ok3 {
		// signature is not valid
	} else {
		// signature is valid, it is safe to use the data
		println(string(data3))
	}
}
```



### Performance / Testing

To run the tests and benchmarks, use the following command.

```sh
go test -bench=. -v
```
