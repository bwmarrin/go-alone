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

Baby steps :)



### Performance / Testing

To run the tests and benchmarks, use the following command.

```sh
go test -bench=. -v
```
