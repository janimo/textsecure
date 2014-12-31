// Copyright (c) 2014 Canonical Ltd.
// Licensed under the GPLv3, see the COPYING file for details.

package textsecure

import (
	"encoding/base64"
	"github.com/golang/protobuf/proto"
	"github.com/zmanian/textsecure/protobuf"
	"golang.org/x/net/websocket"
	"log"
	"net/url"
	"strings"
	"time"

	"crypto/tls"
)

type WSConn struct {
	conn *websocket.Conn
	id   uint64
}

func NewWSConn(originURL, user, pass string, skipTLSCheck bool) *WSConn {
	v := url.Values{}
	v.Set("login", user)
	v.Set("password", pass)
	params := v.Encode()
	wsURL := strings.Replace(originURL, "http", "ws", 1) + "?" + params

	wsConfig, err := websocket.NewConfig(wsURL, originURL)
	if err != nil {
		log.Fatal(err)
	}
	if config.SkipTLSCheck {
		wsConfig.TlsConfig = &tls.Config{InsecureSkipVerify: true}
	}

	wsc, err := websocket.DialConfig(wsConfig)
	if err != nil {
		log.Fatal(err)
	}
	return &WSConn{conn: wsc}
}

func (wsc *WSConn) send(b []byte) {
	websocket.Message.Send(wsc.conn, b)
}

func (wsc *WSConn) receive() ([]byte, error) {
	var b []byte
	err := websocket.Message.Receive(wsc.conn, &b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (wsc *WSConn) sendRequest(verb, path string, body []byte, id *uint64) {
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

type wsAck struct {
	Id   uint64 `json:"id"`
	Type int    `json:"type"`
}

func (wsc *WSConn) keepAlive() {
	for {
		//		wsc.sendRequest("GET", "/v1/keepalive", nil, nil)
		pingMsg := wsAck{Id: 0, Type: 1}
		websocket.JSON.Send(wsc.conn, pingMsg)

		time.Sleep(time.Second * 5)
	}
}

func (wsc *WSConn) sendAck(id uint64) {
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

func (wsc *WSConn) Get(url string) (*Response, error) {
	wsc.id++
	wsc.sendRequest("GET", url, nil, &wsc.id)
	wsc.receive()
	return nil, nil
}

func (wsc *WSConn) Put(url string, body []byte) (*Response, error) {
	wsc.id++
	wsc.sendRequest("PUT", url, body, &wsc.id)
	return nil, nil
}

func ListenForMessages() {
	wsc := NewWSConn(config.Server+"/v1/websocket", config.Tel, registrationInfo.password, config.SkipTLSCheck)

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

		if config.Server == "https://textsecure-service-staging.whispersystems.org:443" {
			m := wsm.GetRequest().GetBody()

			err = handleReceivedMessage(m)
			if err != nil {
				log.Println(err)
				continue
			}

		} else {
			m, err := base64.StdEncoding.DecodeString(string(wsm.GetRequest().GetBody()))
			if err != nil {
				log.Println("WebSocketMessageRequest decode", err)
				continue

				err = handleReceivedMessage(m)
				if err != nil {
					log.Println(err)
					continue
				}
			}
		}
		wsc.sendAck(wsm.GetRequest().GetId())
	}
}
