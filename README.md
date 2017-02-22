<img align="right" src="https://raw.githubusercontent.com/wiki/bwmarrin/go-alone/8bitsword.png">
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
tokens however they are not compatible with each other. go-alone uses a faster
integer optimized base58 coding for timestamps and does not have the "Salt" or
serializer features of itsdangerous. Both of those things can still be 
accomplished. You can prepend your "Salt" key to the secret (this is how salting 
is done in itsdangerous) and use any of the existing Go serializers before 
passing the data to go-alone for signing.

go-alone tokens solve a similar problem to what [JSON Web Tokens](https://jwt.io/)
solve. However go-alone tokens are smaller so they take less bandwidth and time
to transmit across networks and of course less space to store.  

**For help with this package or general Go discussion, please join the [Discord 
Gophers](https://discord.gg/0f1SbxBZjYq9jLBk) chat server.**

## Status @ 2017-02-21
This package should **NOT** be considered stable and completed. While I feel the
majority of this package is where I want it to be - there is still a good chance
of some breaking changes in the near future.  I would guess within a month I will
have the API stable/locked.

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
