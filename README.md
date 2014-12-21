#A TextSecure package in Go

** WARNING: this is alpha quality. While 1-1 messaging works, there are still bugs **

This is a simple Go package aiming to implement the networking and cryptographic
protocols used by TextSecure's **push data** feature. (i.e. not encrypted SMS)

The included sample command line app can send and receive messages, but cannot yet
handle attachments or group messages yet, and there are still plenty of bugs left.

The API presented by the package is definitely not final.

# Installation and usage

## Ubuntu 14.10

    aptitude install golang mercurial gccgo-go
    mkdir ~/go/bin; export GOPATH=~/go; export PATH=$PATH:$GOPATH
    go get github.com/janimo/textsecure/
    cd ~/go/src/github.com/janimo/textsecure/cmd
    go build
    ./textsecure

