# Simple and incomplete TextSecure command line client to test the package

** At the moment only 1-1 messaging is supported, no attachments, no group chats **

Installation
------------

    go get github.com/janimo/textsecure/cmd/textsecure

Configuration
-------------

Copy .config to a directory and modify it, then run the tool from that directory.
It will create .storage to hold all the protocol state. Removing that dir and running
the tool again will trigger a reregistration with the server.

Usage
-----

    textsecure -h
