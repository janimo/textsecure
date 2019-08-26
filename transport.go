// Copyright (c) 2014 Canonical Ltd.
// Licensed under the GPLv3, see the COPYING file for details.

package textsecure

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	log "github.com/sirupsen/logrus"
)

var transport transporter

func setupTransporter() {
	setupCA()
	transport = newHTTPTransporter(config.Server, config.Tel, registrationInfo.password)
}

type response struct {
	Status int
	Body   io.ReadCloser
}

func (r *response) isError() bool {
	return r.Status < 200 || r.Status >= 300
}

func (r *response) Error() string {
	return fmt.Sprintf("status code %d\n", r.Status)
}

type transporter interface {
	get(url string) (*response, error)
	del(url string) (*response, error)
	putJSON(url string, body []byte) (*response, error)
	putBinary(url string, body []byte) (*response, error)
}

type httpTransporter struct {
	baseURL string
	user    string
	pass    string
	client  *http.Client
}

func getProxy(req *http.Request) (*url.URL, error) {
	if config.ProxyServer != "" {
		u, err := url.Parse(config.ProxyServer)
		if err == nil {
			return u, nil
		}
	}
	return http.ProxyFromEnvironment(req)
}

func newHTTPClient() *http.Client {
	client := &http.Client{
		Transport: &http.Transport{
			TLSHandshakeTimeout: 30 * time.Second,
		},
		Timeout: 45 * time.Second,
	}

	return client
}

func newHTTPTransporter(baseURL, user, pass string) *httpTransporter {
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: rootCA},
			Proxy:           getProxy,
		},
	}

	return &httpTransporter{baseURL, user, pass, client}
}

func (ht *httpTransporter) get(url string) (*response, error) {
	req, err := http.NewRequest("GET", ht.baseURL+url, nil)
	if err != nil {
		return nil, err
	}
	if config.UserAgent != "" {
		req.Header.Set("X-Signal-Agent", config.UserAgent)
	}
	req.SetBasicAuth(ht.user, ht.pass)
	resp, err := ht.client.Do(req)
	if err != nil {
		return nil, err
	}
	r := &response{}
	if resp != nil {
		r.Status = resp.StatusCode
		r.Body = resp.Body
	}

	log.Debugf("GET %s %d\n", url, r.Status)

	return r, err
}

func (ht *httpTransporter) del(url string) (*response, error) {
	req, err := http.NewRequest("DELETE", ht.baseURL+url, nil)
	if err != nil {
		return nil, err
	}
	if config.UserAgent != "" {
		req.Header.Set("X-Signal-Agent", config.UserAgent)
	}
	req.SetBasicAuth(ht.user, ht.pass)
	resp, err := ht.client.Do(req)
	if err != nil {
		return nil, err
	}
	r := &response{}
	if resp != nil {
		r.Status = resp.StatusCode
		r.Body = resp.Body
	}

	log.Debugf("DELETE %s %d\n", url, r.Status)

	return r, err
}

func (ht *httpTransporter) put(url string, body []byte, ct string) (*response, error) {
	br := bytes.NewReader(body)
	req, err := http.NewRequest("PUT", ht.baseURL+url, br)
	if err != nil {
		return nil, err
	}
	if config.UserAgent != "" {
		req.Header.Set("X-Signal-Agent", config.UserAgent)
	}
	req.Header.Add("Content-Type", ct)
	req.SetBasicAuth(ht.user, ht.pass)
	resp, err := ht.client.Do(req)
	if err != nil {
		return nil, err
	}
	r := &response{}
	if resp != nil {
		r.Status = resp.StatusCode
		r.Body = resp.Body
	}

	log.Debugf("PUT %s %d\n", url, r.Status)

	return r, err
}

func (ht *httpTransporter) putJSON(url string, body []byte) (*response, error) {
	return ht.put(url, body, "application/json")
}

func (ht *httpTransporter) putBinary(url string, body []byte) (*response, error) {
	return ht.put(url, body, "application/octet-stream")
}
