# Simple and incomplete TextSecure command line client to test the package

** At the moment only 1-1 messaging is supported, no attachments, no group chats **

Installation
------------

    go get github.com/zmanian/textsecure/cmd/textsecure

For more details, including setting up Go, check the [wiki] (https://github.com/zmanian/textsecure/wiki/Installation)

Configuration
-------------

Copy .config to a directory and modify it, then run the tool from that directory.
It will create .storage to hold all the protocol state. Removing that dir and running
the tool again will trigger a reregistration with the server.

Usage
-----
** Do not run multiple instances of the app from the same directory, it (and the server) can get confused **

This will show the supported command line flags

    textsecure -h

Running the command without arguments will put it in receiving mode, and once it receives a message it will
be able to talk to that contact.

Connecting to the staging server.

Text Secure runs a staging server where pre-production server side features and protocols can be tested.

To use with the testing server change the server in config.yml to https://textsecure-service-staging.whispersystems.org:443

The staging server maintains a seperate key and identifier registration databased from the production server so you will have to re-register. The same identifier can be used on both servers.


Discussions
-----------

User and developer discussions happen on the [mailing list] (https://groups.google.com/forum/#!forum/textsecure-go)
