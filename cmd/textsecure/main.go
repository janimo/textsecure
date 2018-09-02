package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
        "os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"gopkg.in/yaml.v2"

	"github.com/aebruno/textsecure"
	"github.com/aebruno/textsecure/axolotl"
	"golang.org/x/crypto/ssh/terminal"
)

// Simple command line test app for TextSecure.
// It can act as an echo service, send one-off messages and attachments,
// or carry on a conversation with another client

var (
	echo         bool
	to           string
	group        bool
	message      string
	attachment   string
	newgroup     string
	updategroup  string
	leavegroup   string
	endsession   bool
	showdevices  bool
	linkdevice   string
	unlinkdevice int
	configDir    string
	stress       int
	hook         string
	raw          bool
	gateway      bool
	bind         string
)

func init() {
	flag.BoolVar(&echo, "echo", false, "Act as an echo service")
	flag.StringVar(&to, "to", "", "Contact name to send the message to")
	flag.BoolVar(&group, "group", false, "Destination is a group")
	flag.StringVar(&message, "message", "", "Single message to send, then exit")
	flag.StringVar(&attachment, "attachment", "", "File to attach")
	flag.StringVar(&newgroup, "newgroup", "", "Create a group, the argument has the format 'name:member1:member2'")
	flag.StringVar(&updategroup, "updategroup", "", "Update a group, the argument has the format 'hexid:name:member1:member2'")
	flag.StringVar(&leavegroup, "leavegroup", "", "Leave a group named by the argument")
	flag.BoolVar(&endsession, "endsession", false, "Terminate session with peer")
	flag.BoolVar(&showdevices, "showdevices", false, "Show linked devices")
	flag.StringVar(&linkdevice, "linkdevice", "", "Link a new device, the argument is a url in the format 'tsdevice:/?uuid=xxx&pub_key=yyy'")
	flag.IntVar(&unlinkdevice, "unlinkdevice", 0, "Unlink a device, the argument is the id of the device to delete")
	flag.IntVar(&stress, "stress", 0, "Automatically send many messages to the peer")
	flag.StringVar(&configDir, "config", ".config", "Location of config dir")
        flag.StringVar(&hook, "hook", "", "Program/Script to call when message is received (e.g. for bot usage)")
        flag.BoolVar(&raw, "raw", false, "raw mode, disable ansi colors")
        flag.BoolVar(&gateway, "gateway", false, "http gateway mode")
        flag.StringVar(&bind, "bind", "localhost:5000", "bind address and port when in gateway-mode")
}

var (
	red    = "\x1b[31m"
	green  = "\x1b[32m"
	yellow = "\x1b[33m"
	blue   = "\x1b[34m"
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

func getConfig() (*textsecure.Config, error) {
	return textsecure.ReadConfig(configDir + "/config.yml")
}

func getLocalContacts() ([]textsecure.Contact, error) {
	return textsecure.ReadContacts(configDir + "/contacts.yml")
}

func sendMessage(isGroup bool, to, message string) error {
	var err error
	if isGroup {
		_, err = textsecure.SendGroupMessage(to, message)
	} else {
		_, err = textsecure.SendMessage(to, message)
		if nerr, ok := err.(axolotl.NotTrustedError); ok {
			fmt.Printf("Peer identity not trusted. Remove the file .storage/identity/remote_%s to approve\n", nerr.ID)
		}
	}
	return err
}

func sendAttachment(isGroup bool, to, message string, f io.Reader) error {
	var err error
	if isGroup {
		_, err = textsecure.SendGroupAttachment(to, message, f)
	} else {
		_, err = textsecure.SendAttachment(to, message, f)
		if nerr, ok := err.(axolotl.NotTrustedError); ok {
			fmt.Printf("Peer identity not trusted. Remove the file .storage/identity/remote_%s to approve\n", nerr.ID)
		}
	}
	return err
}

// conversationLoop sends messages read from the console
func conversationLoop(isGroup bool) {
	for {
		var message string
		if raw {
			message = readLine(fmt.Sprintf(""))
		} else {
			message = readLine(fmt.Sprintf("%s>", blue))
		}
		if message == "" {
			continue
		}

		err := sendMessage(isGroup, to, message)

		if err != nil {
			log.Println(err)
		}
	}
}

func messageHandler(msg *textsecure.Message) {
	if echo {
		to := msg.Source()
		if msg.Group() != nil {
			to = msg.Group().Hexid
		}
		err := sendMessage(msg.Group() != nil, to, msg.Message())

		if err != nil {
			log.Println(err)
		}
		return
	}

	if msg.Message() != "" {
		fmt.Printf("\r                                               %s%s\n>", pretty(msg), blue)
		if hook != "" {
			hookProcess := exec.Command(hook,pretty(msg))
			hookProcess.Start()
			hookProcess.Wait()
		}
		if ! raw {
			fmt.Printf("\r                                               %s%s\n>", pretty(msg), blue)
		}
	}

	for _, a := range msg.Attachments() {
		handleAttachment(msg.Source(), a.R)
	}

	// if no peer was specified on the command line, start a conversation with the first one contacting us
	if to == "" {
		to = msg.Source()
		isGroup := false
		if msg.Group() != nil {
			isGroup = true
			to = msg.Group().Hexid
		}
		go conversationLoop(isGroup)
	}
}

func handleAttachment(src string, r io.Reader) {
	f, err := ioutil.TempFile(".", "TextSecure_Attachment")
	if err != nil {
		log.Println(err)
		return
	}
	l, err := io.Copy(f, r)
	if err != nil {
		log.Println(err)
		return
	}
	log.Printf("Saving attachment of length %d from %s to %s", l, src, f.Name())
}

var timeFormat = "Mon 03:04"

func timestamp(msg *textsecure.Message) string {
	t := time.Unix(0, int64(msg.Timestamp())*1000000)
	return t.Format(timeFormat)
}

func pretty(msg *textsecure.Message) string {
	src := getName(msg.Source())
	if msg.Group() != nil {
		src = src + "[" + msg.Group().Name + "]"
	}
	if raw {
		return fmt.Sprintf("%s %s %s", timestamp(msg), src, msg.Message())
	}
	return fmt.Sprintf("%s%s %s%s %s%s", yellow, timestamp(msg), red, src, green, msg.Message())
}

// getName returns the local contact name corresponding to a phone number,
// or failing to find a contact the phone number itself
func getName(tel string) string {
	if n, ok := telToName[tel]; ok {
		return n
	}
	return tel
}

func registrationDone() {
	log.Println("Registration done.")
}

// GroupFile loads group info from file
type GroupFile struct {
	ID      []byte
	Hexid   string
	Flags   uint32
	Name    string
	Members []string
	Avatar  io.Reader `yaml:"-"`
}

// Group as json object for output
type Group struct {
	Name string    `json:"name"`
}

// GroupsHandler will return all known groups as json
func GroupsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type","application/json")

	data := make(map[string]Group)

	filepath.Walk(".storage/groups", func(path string, info os.FileInfo, e error) error {
		if info.Mode().IsRegular() {
			b, err := ioutil.ReadFile(path)
			if err != nil {
				return err
			}

			group := &GroupFile{}
			err = yaml.Unmarshal(b, group)
			if err != nil {
				return err
			}
			data[group.Hexid] = Group{Name: group.Name}
		}
		return nil
	})
	json.NewEncoder(w).Encode(data)
}

// RekeyHandler will delete existing peer identity
func RekeyHandler(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type","application/json")

	if r.Method != "DELETE" {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "{\"success\": false}")
	}

	identity := r.URL.Path[len("/rekey/"):]
	isIdentity := regexp.MustCompile(`^\d*$`).MatchString(identity)
	if isIdentity {
		filename := []string{".storage/identity/remote", identity}
		err := os.Remove(strings.Join(filename, "_"))
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
                        fmt.Fprintf(w, "{\"success\": false, \"error\": \"identity %s not found\"}", identity)
		} else {
			fmt.Fprintf(w, "{\"success\": true}")
		}
	} else {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "{\"success\": false}")
	}
}

// GatewayHandler to receive POST data, process and send
func GatewayHandler(w http.ResponseWriter, r *http.Request) {

        w.Header().Set("Content-Type","application/json")

        if r.Method != "POST" {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "{\"success\": false}")
        }

        message := r.FormValue("message")
        to := r.FormValue("to")

        if len(message) > 0 && len(to) > 0 {
		httpstatus := http.StatusOK
		errormessage := "unknown"
		isGroup := regexp.MustCompile(`^([a-fA-F\d]{32})$`).MatchString(to)
		err := sendMessage(isGroup, to, message)
		if err != nil {
			switch {
			case regexp.MustCompile(`status code 413`).MatchString(err.Error()):
				httpstatus = http.StatusRequestEntityTooLarge
				errormessage = "signal api rate limit reached"
			case regexp.MustCompile(`remote identity \d+ is not trusted`).MatchString(err.Error()):
				httpstatus = http.StatusInternalServerError
				errormessage = "remote identity is not trusted"
			}
			w.WriteHeader(httpstatus)
			fmt.Fprintf(w, "{\"success\": false, \"error\": \"%s\"}", errormessage)
		} else {
			w.WriteHeader(httpstatus)
	                fmt.Fprintf(w, "{\"success\": true}")
		}
        } else {
		w.WriteHeader(http.StatusInternalServerError)
                fmt.Fprintf(w, "{\"success\": false, \"error\": \"form fields message and to are required\"}")
        }
}

var telToName map[string]string

func main() {
	flag.Parse()
	log.SetFlags(0)
	client := &textsecure.Client{
		GetConfig:           getConfig,
		GetLocalContacts:    getLocalContacts,
		GetVerificationCode: getVerificationCode,
		GetStoragePassword:  getStoragePassword,
		MessageHandler:      messageHandler,
		RegistrationDone:    registrationDone,
	}
	err := textsecure.Setup(client)
	if err != nil {
		log.Fatal(err)
	}

	if gateway {
		http.HandleFunc("/", GatewayHandler)
		http.HandleFunc("/groups", GroupsHandler)
		http.HandleFunc("/rekey/", RekeyHandler)
		log.Fatal(http.ListenAndServe(bind, nil))
	}

	if linkdevice != "" {
		log.Printf("Linking new device with url: %s", linkdevice)
		url, err := url.Parse(linkdevice)
		if err != nil {
			log.Fatal(err)
		}

		uuid := url.Query().Get("uuid")
		pk := url.Query().Get("pub_key")
		code, err := textsecure.NewDeviceVerificationCode()
		if err != nil {
			log.Fatal(err)
		}

		err = textsecure.AddDevice(uuid, pk, code)
		if err != nil {
			log.Fatal(err)
		}
		return
	}

	if unlinkdevice > 0 {
		err = textsecure.UnlinkDevice(unlinkdevice)
		if err != nil {
			log.Fatal(err)
		}
		return
	}

	if showdevices {
		devs, err := textsecure.LinkedDevices()
		if err != nil {
			log.Fatal(err)
		}

		for _, d := range devs {
			log.Printf("ID: %d\n", d.ID)
			log.Printf("Name: %s\n", d.Name)
			log.Printf("Created: %d\n", d.Created)
			log.Printf("LastSeen: %d\n", d.LastSeen)
			log.Println("============")
		}
		return
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

		if newgroup != "" {
			s := strings.Split(newgroup, ":")
			textsecure.NewGroup(s[0], s[1:])
			return
		}
		if updategroup != "" {
			s := strings.Split(updategroup, ":")
			textsecure.UpdateGroup(s[0], s[1], s[2:])
			return
		}
		if leavegroup != "" {
			textsecure.LeaveGroup(leavegroup)
			return
		}
		// If "to" matches a contact name then get its phone number, otherwise assume "to" is a phone number
		for _, c := range contacts {
			if strings.EqualFold(c.Name, to) {
				to = c.Tel
				break
			}
		}

		if to != "" {
			// Terminate the session with the peer
			if endsession {
				textsecure.EndSession(to, "TERMINATE")
				return
			}

			// Send attachment with optional message then exit
			if attachment != "" {
				f, err := os.Open(attachment)
				if err != nil {
					log.Fatal(err)
				}

				err = sendAttachment(group, to, message, f)
				if err != nil {
					log.Fatal(err)
				}
				return
			}

			if stress > 0 {
				c := make(chan int, stress)
				for i := 0; i < stress; i++ {
					go func(i int) {
						sendMessage(false, to, fmt.Sprintf("Stress %d\n", i))
						c <- i
					}(i)
				}
				for i := 0; i < stress; i++ {
					<-c
				}
				return
			}

			// Send a message then exit
			if message != "" {
				err := sendMessage(group, to, message)
				if err != nil {
					log.Fatal(err)
				}
				return
			}

			// Enter conversation mode
			go conversationLoop(group)
		}
	}

	err = textsecure.StartListening()
	if err != nil {
		log.Println(err)
	}
}
