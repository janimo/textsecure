// Copyright (c) 2014 Canonical Ltd.
// Licensed under the GPLv3, see the COPYING file for details.

package textsecure

import (
	"bytes"
	"crypto/tls"
	"io"
	"log"
	"net/http"
)

var transporter Transporter

func setupTransporter() {
	transporter = NewHTTPTransporter(config.Server, config.Tel, registrationInfo.password, config.SkipTLSCheck)
}

type Response struct {
	Status int
	Body   io.ReadCloser
}

func (r *Response) isError() bool {
	return r.Status != 200 && r.Status != 204
}

type Transporter interface {
	Get(url string) (*Response, error)
	PutJSON(url string, body []byte) (*Response, error)
	PutBinary(url string, body []byte) (*Response, error)
}

type HTTPTransporter struct {
	baseURL string
	user    string
	pass    string
	client  *http.Client
}

func NewHTTPTransporter(baseURL, user, pass string, skipTLSCheck bool) *HTTPTransporter {
	client := &http.Client{}
	if skipTLSCheck {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	return &HTTPTransporter{baseURL, user, pass, client}
}

func (ht *HTTPTransporter) Get(url string) (*Response, error) {
	req, err := http.NewRequest("GET", ht.baseURL+url, nil)
	req.SetBasicAuth(ht.user, ht.pass)
	resp, err := ht.client.Do(req)
	r := &Response{}
	if resp != nil {
		r.Status = resp.StatusCode
		r.Body = resp.Body
	}

	if r.isError() {
		log.Printf("GET %s %d\n", url, r.Status)
	}

	return r, err
}

func (ht *HTTPTransporter) put(url string, body []byte, ct string) (*Response, error) {
	br := bytes.NewReader(body)
	req, err := http.NewRequest("PUT", ht.baseURL+url, br)
	req.Header.Add("Content-type", ct)
	req.SetBasicAuth(ht.user, ht.pass)
	resp, err := ht.client.Do(req)
	r := &Response{}
	if resp != nil {
		r.Status = resp.StatusCode
		r.Body = resp.Body
	}

	if r.isError() {
		log.Printf("PUT %s %d\n", url, r.Status)
	}

	return r, err
}

func (ht *HTTPTransporter) PutJSON(url string, body []byte) (*Response, error) {
	return ht.put(url, body, "application/json")
}

func (ht *HTTPTransporter) PutBinary(url string, body []byte) (*Response, error) {
	return ht.put(url, body, "application/octet-stream")
}
