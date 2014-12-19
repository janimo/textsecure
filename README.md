#A TextSecure package in Go

** WARNING: this is alpha quality. While 1-1 messaging works, there are still bugs **

This is a simple Go package aiming to implement the networking and cryptographic
protocols used by TextSecure's **push data** feature. (i.e. not encrypted SMS)

The included sample command line app can send and receive messages, but cannot yet
handle attachments or group messages yet, and there are still plenty of bugs left.

The API presented by the package is definitely not final.
