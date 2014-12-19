// Copyright (c) 2014 Canonical Ltd.
// Licensed under the GPLv3, see the COPYING file for details.

package textsecure

import (
	"bufio"
	"fmt"
	"log"
	"os"
)

// ConsoleReadLine gets a newline terminated string from the console.
// It is exported to be usable as the default Client.ReadLine callback
func ConsoleReadLine(prompt string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(prompt)
	text, _, err := reader.ReadLine()
	if err != nil {
		log.Fatal("Cannot read line from console: ", err)
	}
	return string(text)
}

func readLine(prompt string) string {
	if client.ReadLine != nil {
		return client.ReadLine(prompt)
	}
	return ConsoleReadLine(prompt)
}
