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

type Session struct {
	to string
}

type Sessions []Session

func findSession(sessions Sessions, recipient string) (int, error) {
	for index, sess := range sessions {
		if sess.to == recipient {
			return index, nil
		}
	}
	return -1, fmt.Errorf("Session not found")
}

var (
	echo          bool
	to            string
	message       string
	attachment    string
	fingerprint   string
	sessions      Sessions
	activeSession *Session
)

func init() {
	flag.BoolVar(&echo, "echo", false, "Act as an echo service")
	flag.StringVar(&to, "to", "", "Contact name to send the message to")
	flag.StringVar(&message, "message", "", "Single message to send, then exit")
	flag.StringVar(&attachment, "attachment", "", "File to attach")
	flag.StringVar(&fingerprint, "fingerprint", "", "Name of contact to get identity key fingerprint")
}

var (
	green = "\x1b[32m"
	blue  = "\x1b[34m"
)

// echoMessageHandler simply echoes what is was sent
func echoMessageHandler(source string, message string) {
	err := textsecure.SendMessage(source, message)
	if err != nil {
		log.Println(err)
	}
}

// conversationLoop sends messages read from the console
func conversationLoop() {
	for {
		message := textsecure.ConsoleReadLine(fmt.Sprintf("%s%s>", blue, activeSession.to))
		if message == "" {
			continue
		}
		textsecure.SendMessage(activeSession.to, message)

	}
}

// conversationMessageHandler prints messages received
func conversationMessageHandler(source string, message string) {

	fmt.Printf("\rSource:%s\n                                               %s%s%s\n>", source, green, message, blue)
	// if no peer was specified on the command line, start a conversation with the first one contacting us
	i, err := findSession(sessions, source)
	if err != nil {
		sessions = append(sessions, Session{to: source})
		activeSession = &sessions[len(sessions)-1]

	} else {
		activeSession = &sessions[i]

	}
	go conversationLoop()
}

func main() {
	flag.Parse()
	log.SetFlags(0)
	client := &textsecure.Client{
		RootDir:        ".",
		ReadLine:       textsecure.ConsoleReadLine,
		MessageHandler: conversationMessageHandler,
	}
	textsecure.Setup(client)

	// Enter echo mode
	if echo {
		client.MessageHandler = echoMessageHandler
		textsecure.ListenForMessages()
	}

	// If "to" matches a contact name then get its phone number, otherwise assume "to" is a phone number
	for _, c := range textsecure.GetRegisteredContacts() {
		if strings.EqualFold(c.Name, to) {
			to = c.Tel
			break
		}
	}

	if fingerprint != "" {
		textsecure.ShowFingerprint(fingerprint)
		return
	}

	if to != "" {
		sessions = append(sessions, Session{to})
		activeSession = &sessions[0]
		// Send attachment with optional message then exit
		if attachment != "" {
<<<<<<< HEAD
			textsecure.SendAttachment(activeSession.to, message, attachment)
=======
			err := textsecure.SendFileAttachment(to, message, attachment)
			if err != nil {
				log.Fatal(err)
			}
>>>>>>> 60709ab5545f8416364c776edfe491e01a2bbbb0
			return
		}

		// Send a message then exit
		if message != "" {
<<<<<<< HEAD
			textsecure.SendMessage(activeSession.to, message)
=======
			err := textsecure.SendMessage(to, message)
			if err != nil {
				log.Fatal(err)
			}
>>>>>>> 60709ab5545f8416364c776edfe491e01a2bbbb0
			return
		}

		// Enter conversation mode
		go conversationLoop()
	}

	client.AttachmentHandler = func(src string, b []byte) {
		f, err := ioutil.TempFile(".", "TextSecure_Attachment")
		if err != nil {
			log.Println(err)
			return
		}
		log.Printf("Saving attachment of length %d from %s to %s", len(b), src, f.Name())
		f.Write(b)

	}
	textsecure.ListenForMessages()

}
