// Copyright (c) 2014 Canonical Ltd.
// Licensed under the GPLv3, see the COPYING file for details.

package textsecure

import (
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/janimo/textsecure/protobuf"
	"golang.org/x/net/websocket"

	"crypto/tls"
)

type wsConn struct {
	conn *websocket.Conn
	id   uint64
}

func newWSConn(originURL, user, pass string, skipTLSCheck bool) (*wsConn, error) {
	v := url.Values{}
	v.Set("login", user)
	v.Set("password", pass)
	params := v.Encode()
	wsURL := strings.Replace(originURL, "http", "ws", 1) + "?" + params

	wsConfig, err := websocket.NewConfig(wsURL, originURL)
	if err != nil {
		return nil, err
	}
	if config.SkipTLSCheck {
		wsConfig.TlsConfig = &tls.Config{InsecureSkipVerify: true}
	}

	wsc, err := websocket.DialConfig(wsConfig)
	if err != nil {
		return nil, err
	}
	return &wsConn{conn: wsc}, nil
}

func (wsc *wsConn) send(b []byte) {
	websocket.Message.Send(wsc.conn, b)
}

func (wsc *wsConn) receive() ([]byte, error) {
	var b []byte
	err := websocket.Message.Receive(wsc.conn, &b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (wsc *wsConn) sendRequest(verb, path string, body []byte, id *uint64) {
	typ := textsecure.WebSocketMessage_REQUEST

	wsm := &textsecure.WebSocketMessage{
		Type: &typ,
		Request: &textsecure.WebSocketRequestMessage{
			Verb: &verb,
			Path: &path,
			Body: body,
			Id:   id,
		},
	}

	b, err := proto.Marshal(wsm)
	if err != nil {
		log.Printf("WebSocketMessage marshal error in sendRequest: %s", err)
		return
	}
	wsc.send(b)
}

func (wsc *wsConn) keepAlive() {
	for {
		wsc.sendRequest("GET", "/v1/keepalive", nil, nil)
		time.Sleep(time.Second * 15)
	}
}

func (wsc *wsConn) sendAck(id uint64) {
	typ := textsecure.WebSocketMessage_RESPONSE
	message := "OK"
	status := uint32(200)

	wsm := &textsecure.WebSocketMessage{
		Type: &typ,
		Response: &textsecure.WebSocketResponseMessage{
			Id:      &id,
			Status:  &status,
			Message: &message,
		},
	}

	b, err := proto.Marshal(wsm)
	if err != nil {
		log.Println("Could not marshal ack message", err)
	}
	wsc.send(b)
}

func (wsc *wsConn) get(url string) (*response, error) {
	wsc.id++
	wsc.sendRequest("GET", url, nil, &wsc.id)
	wsc.receive()
	return nil, nil
}

func (wsc *wsConn) put(url string, body []byte) (*response, error) {
	wsc.id++
	wsc.sendRequest("PUT", url, body, &wsc.id)
	return nil, nil
}

// ListenForMessages connects to the server and handles incoming websocket messages.
func ListenForMessages() error {
	wsc, err := newWSConn(config.Server+"/v1/websocket", config.Tel, registrationInfo.password, config.SkipTLSCheck)
	if err != nil {
		return fmt.Errorf("Could not establish websocket connection: %s\n", err)
	}

	go wsc.keepAlive()

	for {
		bmsg, err := wsc.receive()
		if err != nil {
			log.Println(err)
			time.Sleep(3 * time.Second)
			continue
		}

		wsm := &textsecure.WebSocketMessage{}
		err = proto.Unmarshal(bmsg, wsm)
		if err != nil {
			log.Println("WebSocketMessage unmarshal", err)
			continue
		}
		m := wsm.GetRequest().GetBody()
		err = handleReceivedMessage(m)
		if err != nil {
			log.Println(err)
			continue
		}
		wsc.sendAck(wsm.GetRequest().GetId())
	}
}
