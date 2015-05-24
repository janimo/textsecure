// Copyright (c) 2014 Canonical Ltd.
// Licensed under the GPLv3, see the COPYING file for details.

package textsecure

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
)

var transport transporter

func setupTransporter() {
	transport = newHTTPTransporter(config.Server, config.Tel, registrationInfo.password, config.SkipTLSCheck)
}

type response struct {
	Status int
	Body   io.ReadCloser
}

func (r *response) isError() bool {
	return r.Status < 200 || r.Status >= 300
}

func (r *response) Error() string {
	return fmt.Sprintf("Status code %d\n", r.Status)
}

type transporter interface {
	get(url string) (*response, error)
	putJSON(url string, body []byte) (*response, error)
	putBinary(url string, body []byte) (*response, error)
}

type httpTransporter struct {
	baseURL string
	user    string
	pass    string
	client  *http.Client
}

func newHTTPTransporter(baseURL, user, pass string, skipTLSCheck bool) *httpTransporter {
	client := &http.Client{}
	if skipTLSCheck {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}
	client.Transport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
	}

	return &httpTransporter{baseURL, user, pass, client}
}

func (ht *httpTransporter) get(url string) (*response, error) {
	req, err := http.NewRequest("GET", ht.baseURL+url, nil)
	req.SetBasicAuth(ht.user, ht.pass)
	resp, err := ht.client.Do(req)
	r := &response{}
	if resp != nil {
		r.Status = resp.StatusCode
		r.Body = resp.Body
	}

	if r.isError() {
		log.Printf("GET %s %d\n", url, r.Status)
	}

	return r, err
}

func (ht *httpTransporter) put(url string, body []byte, ct string) (*response, error) {
	br := bytes.NewReader(body)
	req, err := http.NewRequest("PUT", ht.baseURL+url, br)
	req.Header.Add("Content-type", ct)
	req.SetBasicAuth(ht.user, ht.pass)
	resp, err := ht.client.Do(req)
	r := &response{}
	if resp != nil {
		r.Status = resp.StatusCode
		r.Body = resp.Body
	}

	if r.isError() {
		log.Printf("PUT %s %d\n", url, r.Status)
	}

	return r, err
}

func (ht *httpTransporter) putJSON(url string, body []byte) (*response, error) {
	return ht.put(url, body, "application/json")
}

func (ht *httpTransporter) putBinary(url string, body []byte) (*response, error) {
	return ht.put(url, body, "application/octet-stream")
}
