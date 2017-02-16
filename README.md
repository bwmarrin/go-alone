<img align="right" src="http://vignette1.wikia.nocookie.net/zelda/images/2/28/Hyrule_Warriors_Hylian_Sword_8-Bit_Wooden_Sword_(8-bit_Hylian_Sword).png">
It's dangerous to **go-alone**! Take this.

[![GoDoc](https://godoc.org/github.com/bwmarrin/go-alone?status.svg)](https://godoc.org/github.com/bwmarrin/go-alone) [![Go report](http://goreportcard.com/badge/bwmarrin/go-alone)](http://goreportcard.com/report/bwmarrin/go-alone) [![Build Status](https://travis-ci.org/bwmarrin/go-alone.svg?branch=master)](https://travis-ci.org/bwmarrin/go-alone) [![Coverage](http://gocover.io/_badge/github.com/bwmarrin/go-alone)](https://gocover.io/github.com/bwmarrin/go-alone) [![Discord Gophers](https://img.shields.io/badge/Discord%20Gophers-%23info-blue.svg)](https://discord.gg/0f1SbxBZjYq9jLBk)

go-alone is a [Go](https://golang.org/) package that provides A very simple to 
use HMAC signer and unsigner that tries to be fairly performant.  This is useful
for one-time email tokens, authentication tokens, or to cryptographically sign 
any arbitrary data so that it can be transmitted or stored in an unsecure way 
but is tamper proof so when it comes back to you, you can verify that it is 
exactly the same data that you originally signed.

The development of go-alone was highly influenced by the popular [itsdangerous](http://pythonhosted.org/itsdangerous/)
python library.  The tokens go-alone creates are very similar to itsdangerous 
tokens and there is a degree of compatibility with itsdangerous tokens.  
Reference the itsdangerous_test.go for examples on how to work with itsdangerous
tokens using go-alone.

go-alone tokens solve a similar problem to what JWT tokens solve. However
go-alone tokens are smaller so they take less bandwidth and time to transmit 
across networks and of course less space to store.  

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

See the example folder for a program that demonstrates using this package.

### Performance / Testing

To run the tests and benchmarks, use the following command.

```sh
go test -bench=. -v
```
