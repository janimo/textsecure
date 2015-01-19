package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/janimo/textsecure"
	"golang.org/x/crypto/ssh/terminal"
)

// Simple command line test app for TextSecure.
// It can act as an echo service, send one-off messages and attachments,
// or carry on a conversation with another client

var (
	echo       bool
	to         string
	group      bool
	message    string
	attachment string
)

func init() {
	flag.BoolVar(&echo, "echo", false, "Act as an echo service")
	flag.StringVar(&to, "to", "", "Contact name to send the message to")
	flag.BoolVar(&group, "group", false, "Destination is a group")
	flag.StringVar(&message, "message", "", "Single message to send, then exit")
	flag.StringVar(&attachment, "attachment", "", "File to attach")
}

var (
	red   = "\x1b[31m"
	green = "\x1b[32m"
	blue  = "\x1b[34m"
)

func readLine(prompt string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(prompt)
	text, _, err := reader.ReadLine()
	if err != nil {
		log.Fatal("Cannot read line from console: ", err)
	}
	return string(text)
}

func getVerificationCode() string {
	return readLine("Enter verification code>")
}

func getStoragePassword() string {
	fmt.Printf("Input storage password>")
	password, err := terminal.ReadPassword(0)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println()
	return string(password)
}

// conversationLoop sends messages read from the console
func conversationLoop(isGroup bool) {
	for {
		message := readLine(fmt.Sprintf("%s>", blue))
		if message == "" {
			continue
		}
		var err error
		if isGroup {
			err = textsecure.SendGroupMessage(to, message)
		} else {
			err = textsecure.SendMessage(to, message)
		}
		if err != nil {
			log.Println(err)
		}
	}
}

func messageHandler(msg *textsecure.Message) {
	if echo {
		if msg.Group() != "" {
			textsecure.SendGroupMessage(msg.Group(), msg.Message())
			return
		}
		err := textsecure.SendMessage(msg.Source(), msg.Message())
		if err != nil {
			log.Println(err)
		}
		return
	}

	if msg.Message() != "" {
		fmt.Printf("\r                                               %s%s : %s%s%s\n>", red, pretty(msg), green, msg.Message(), blue)
	}

	for _, a := range msg.Attachments() {
		handleAttachment(msg.Source(), a)
	}

	// if no peer was specified on the command line, start a conversation with the first one contacting us
	if to == "" {
		to = msg.Source()
		isGroup := false
		if msg.Group() != "" {
			isGroup = true
			to = msg.Group()
		}
		go conversationLoop(isGroup)
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

func pretty(msg *textsecure.Message) string {
	m := getName(msg.Source())
	if msg.Group() != "" {
		m = m + "[" + msg.Group() + "]"
	}
	return m
}

// getName returns the local contact name corresponding to a phone number,
// or failing to find a contact the phone number itself
func getName(tel string) string {
	if n, ok := telToName[tel]; ok {
		return n
	}
	return tel
}

var telToName map[string]string

func main() {
	flag.Parse()
	log.SetFlags(0)
	client := &textsecure.Client{
		RootDir:             ".",
		GetVerificationCode: getVerificationCode,
		GetStoragePassword:  getStoragePassword,
		MessageHandler:      messageHandler,
	}
	err := textsecure.Setup(client)
	if err != nil {
		log.Fatal(err)
	}

	if !echo {
		contacts, err := textsecure.GetRegisteredContacts()
		if err != nil {
			log.Printf("Could not get contacts: %s\n", err)
		}

		telToName = make(map[string]string)
		for _, c := range contacts {
			telToName[c.Tel] = c.Name
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
			go conversationLoop(false)
		}
	}

	err = textsecure.ListenForMessages()
	if err != nil {
		log.Println(err)
	}
}
