// Copyright (c) 2014 Canonical Ltd.
// Licensed under the GPLv3, see the COPYING file for details.

package textsecure

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
)

// getAttachment downloads an encrypted attachment blob from the given URL
func getAttachment(url string) (io.ReadCloser, error) {
	req, err := http.NewRequest("GET", url, nil)
	req.Header.Add("Content-type", "application/octet-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	return resp.Body, nil
}

// putAttachment uploads an encrypted attachment to the given URL
func putAttachment(url string, body []byte) error {
	br := bytes.NewReader(body)
	req, err := http.NewRequest("PUT", url, br)
	if err != nil {
		return err
	}
	//req.Header.Add("Content-type", "application/octet-stream")
	req.Header.Add("Content-type", "application/octet-stream")
	req.Header.Add("Content-length", strconv.Itoa(len(body)))
	resp, err := http.DefaultClient.Do(req)

	if resp.StatusCode >= 300 {
		return fmt.Errorf("ERROR %d\n", resp.StatusCode)
	}

	return err
}

// uploadAttachment encrypts, authenticates and uploads a given attachment to a location requested from the server
func uploadAttachment(r io.Reader, ct string) (*att, error) {
	//combined AES-256 and HMAC-SHA256 key
	keys := make([]byte, 64)
	randBytes(keys)

	b, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	e, err := aesEncrypt(keys[:32], b)
	if err != nil {
		return nil, err
	}

	m := appendMAC(keys[32:], e)

	id, location, err := allocateAttachment()
	if err != nil {
		return nil, err
	}
	err = putAttachment(location, m)
	if err != nil {
		return nil, err
	}
	return &att{id, ct, keys}, nil
}
