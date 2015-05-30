// Copyright (c) 2014 Canonical Ltd.
// Licensed under the GPLv3, see the COPYING file for details.

package textsecure

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
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

// set up a tunnel via HTTP CONNECT
// see https://gist.github.com/madmo/8548738
func httpConnect(host, wsurl string, wsConfig *websocket.Config) (io.ReadWriteCloser, error) {
	var p net.Conn
	var err error
	if strings.HasPrefix(wsurl, "wss") {
		p, err = tls.Dial("tcp", host, wsConfig.TlsConfig)
	} else {
		p, err = net.Dial("tcp", host)
	}
	if err != nil {
		return nil, err
	}

	turl, err := url.Parse(wsurl)
	if err != nil {
		return nil, err
	}

	req := http.Request{
		Method: "CONNECT",
		URL:    &url.URL{},
		Host:   turl.Host,
	}

	cc := httputil.NewClientConn(p, nil)
	cc.Do(&req)
	if err != nil && err != httputil.ErrPersistEOF {
		return nil, err
	}

	rwc, _ := cc.Hijack()
	return rwc, nil
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

	var wsc *websocket.Conn

	req := http.Request{
		URL: &url.URL{},
	}

	proxyURL, err := http.ProxyFromEnvironment(&req)
	if err != nil {
		return nil, err
	}
	if proxyURL == nil {
		wsc, err = websocket.DialConfig(wsConfig)
		if err != nil {
			return nil, err
		}
	} else {
		rwc, err := httpConnect(proxyURL.Host, wsURL, wsConfig)
		if err != nil {
			return nil, err
		}
		wsc, err = websocket.NewClient(wsConfig, rwc)
		if err != nil {
			return nil, err
		}
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

func (wsc *wsConn) sendRequest(verb, path string, body []byte, id *uint64) error {
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
		return err
	}
	wsc.send(b)
	return nil
}

func (wsc *wsConn) keepAlive() {
	for {
		err := wsc.sendRequest("GET", "/v1/keepalive", nil, nil)
		if err != nil {
			log.Println(err)
		}
		time.Sleep(time.Second * 15)
	}
}

func (wsc *wsConn) sendAck(id uint64) error {
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
		return err
	}
	wsc.send(b)
	return nil
}

// ListenForMessages connects to the server and handles incoming websocket messages.
func ListenForMessages() error {
	wsc, err := newWSConn(config.Server+"/v1/websocket/", config.Tel, registrationInfo.password, config.SkipTLSCheck)
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
			log.Println(err)
			continue
		}
		m := wsm.GetRequest().GetBody()
		err = handleReceivedMessage(m)
		if err != nil {
			log.Println(err)
			continue
		}
		err = wsc.sendAck(wsm.GetRequest().GetId())
		if err != nil {
			log.Println(err)
		}
	}
}
