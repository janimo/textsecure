package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"strings"

	"github.com/janimo/textsecure"
)

// Simple command line test app for TextSecure.
// It can act as an echo service, send one-off messages and attachments,
// or carry on a conversation with another client

var (
	echo       bool
	to         string
	message    string
	attachment string
)

func init() {
	flag.BoolVar(&echo, "echo", false, "Act as an echo service")
	flag.StringVar(&to, "to", "", "Contact name to send the message to")
	flag.StringVar(&message, "message", "", "Single message to send, then exit")
	flag.StringVar(&attachment, "attachment", "", "File to attach")
}

var (
	green = "\x1b[32m"
	blue  = "\x1b[34m"
)

// conversationLoop sends messages read from the console
func conversationLoop() {
	for {
		message := textsecure.ConsoleReadLine(fmt.Sprintf("%s>", blue))
		if message == "" {
			continue
		}
		err := textsecure.SendMessage(to, message)
		if err != nil {
			log.Println(err)
		}
	}
}

func messageHandler(source string, message string) {
	if echo {
		err := textsecure.SendMessage(source, message)
		if err != nil {
			log.Println(err)
		}
		return
	}

	fmt.Printf("\r                                               %s%s%s\n>", green, message, blue)
	// if no peer was specified on the command line, start a conversation with the first one contacting us
	if to == "" {
		to = source
		go conversationLoop()
	}
}

func attachmentHandler(src string, b []byte) {
	f, err := ioutil.TempFile(".", "TextSecure_Attachment")
	if err != nil {
		log.Println(err)
		return
	}
	log.Printf("Saving attachment of length %d from %s to %s", len(b), src, f.Name())
	f.Write(b)

}

func main() {
	flag.Parse()
	log.SetFlags(0)
	client := &textsecure.Client{
		RootDir:        ".",
		ReadLine:       textsecure.ConsoleReadLine,
		MessageHandler: messageHandler,
	}
	textsecure.Setup(client)

	// Enter echo mode
	if echo {
		textsecure.ListenForMessages()
	}

	// If "to" matches a contact name then get its phone number, otherwise assume "to" is a phone number
	for _, c := range textsecure.GetRegisteredContacts() {
		if strings.EqualFold(c.Name, to) {
			to = c.Tel
			break
		}
	}

	if to != "" {
		// Send attachment with optional message then exit
		if attachment != "" {
			err := textsecure.SendFileAttachment(to, message, attachment)
			if err != nil {
				log.Fatal(err)
			}
			return
		}

		// Send a message then exit
		if message != "" {
			err := textsecure.SendMessage(to, message)
			if err != nil {
				log.Fatal(err)
			}
			return
		}

		// Enter conversation mode
		go conversationLoop()
	}

	client.AttachmentHandler = attachmentHandler
	textsecure.ListenForMessages()

}
