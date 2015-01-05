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

func getContactName(sourceTel string) string{
    contacts, err := textsecure.GetRegisteredContacts()
    if err != nil {
        log.Printf("Could not get contacts: %s\n", err)
    }
    for _, c := range contacts {
        if strings.EqualFold(c.Tel, sourceTel) {
			return c.Name
		}
    }
    return sourceTel
}

func messageHandler(msg *textsecure.Message) {
	if echo {
		err := textsecure.SendMessage(msg.Source(), msg.Message())
		if err != nil {
			log.Println(err)
		}
		return
	}

	if msg.Message() != "" {
        fmt.Printf("\r                                              %s: %s%s%s\n>", getContactName(msg.Source()),green, msg.Message(), blue)
	}

	for _, a := range msg.Attachments() {
		handleAttachment(msg.Source(), a)
	}

	// if no peer was specified on the command line, start a conversation with the first one contacting us
	if to == "" {
		to = msg.Source()
		go conversationLoop()
	}
}

func handleAttachment(src string, b []byte) {
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

	if !echo {
		contacts, err := textsecure.GetRegisteredContacts()
		if err != nil {
			log.Printf("Could not get contacts: %s\n", err)
		}
		// If "to" matches a contact name then get its phone number, otherwise assume "to" is a phone number
		for _, c := range contacts {
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
	}

	err := textsecure.ListenForMessages()
	if err != nil {
		log.Println(err)
	}
}
