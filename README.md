It's dangerous to go-alone! Take this.
==========================================
[![GoDoc](https://godoc.org/github.com/bwmarrin/go-alone?status.svg)](https://godoc.org/github.com/bwmarrin/go-alone) [![Go report](http://goreportcard.com/badge/bwmarrin/go-alone)](http://goreportcard.com/report/bwmarrin/go-alone) [![Build Status](https://travis-ci.org/bwmarrin/go-alone.svg?branch=master)](https://travis-ci.org/bwmarrin/go-alone) [![Coverage](http://gocover.io/_badge/github.com/bwmarrin/go-alone)](https://gocover.io/github.com/bwmarrin/go-alone) [![Discord Gophers](https://img.shields.io/badge/Discord%20Gophers-%23info-blue.svg)](https://discord.gg/0f1SbxBZjYq9jLBk)

<img align="right" src="https://raw.githubusercontent.com/wiki/bwmarrin/go-alone/8bitsword.png">

go-alone is a [Go](https://golang.org/) package that provides
* Methods to create and verify [MAC](https://en.wikipedia.org/wiki/Message_authentication_code) signatures of data
* Ability to add timestamps to signed tokens and use custom epoch if needed.
* BLAKE2b signatures and Base58 time encoding provides outstanding performance and security.
* A very simple to use API with good documentation.
* Various helper methods for parsing tokens

**For more information, please read the [wiki](https://github.com/bwmarrin/go-alone/wiki)**

**For help with this package or general Go discussion, please join the [Discord 
Gophers](https://discord.gg/0f1SbxBZjYq9jLBk) chat server.**

**For a fast and easy to use snowflake ID library, check out [this](https://github.com/bwmarrin/snowflake)**

## :exclamation: Status @ 2017-02-28
This package should not be considered stable and completed. While I feel the
majority of this package is where I want it to be - there is still a slight chance
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
