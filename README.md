# TextSecure library and command line test client for Go

This is a Go package implementing the TextSecure **push data** (i.e. not encrypted SMS) protocol v3 including the Axolotl ratchet.

The included sample command line app can send and receive text messages and attachments and supports group chat.

**The API presented by the package is in flux**,  mainly driven by the needs of https://github.com/janimo/textsecure-qml

Automatically generated documentation can be found on [GoDoc] (https://godoc.org/github.com/janimo/textsecure)

Installation
------------

This command will install both the library and the test client.

    go get github.com/janimo/textsecure/cmd/textsecure

For more details, including setting up Go, check the [wiki] (https://github.com/janimo/textsecure/wiki/Installation)

Configuration
-------------

Copy cmd/textsecure/.config to a directory and modify it, then run the tool from that directory.
It will create .storage to hold all the protocol state. Removing that dir and running the tool again will trigger a reregistration with the server.

Usage
-----

**Do not run multiple instances of the app from the same directory, it (and the server) can get confused**

This will show the supported command line flags

    textsecure -h

Running the command without arguments will put it in receiving mode, and once it receives a message it will be able to talk to that contact.

Discussions
-----------

User and developer discussions happen on the [mailing list] (https://groups.google.com/forum/#!forum/textsecure-go)
