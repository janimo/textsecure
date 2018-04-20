// Copyright (c) 2014 Canonical Ltd.
// Licensed under the GPLv3, see the COPYING file for details.

package textsecure

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"

	textsecure "github.com/aebruno/textsecure/protobuf"
)

// getAttachment downloads an encrypted attachment blob from the given URL
func getAttachment(url string) (io.ReadCloser, error) {
	req, err := http.NewRequest("GET", url, nil)
	req.Header.Add("Content-Type", "application/octet-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	return resp.Body, nil
}

// putAttachment uploads an encrypted attachment to the given URL
func putAttachment(url string, body []byte) ([]byte, error) {
	fmt.Printf(url)
	br := bytes.NewReader(body)
	req, err := http.NewRequest("PUT", url, br)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/octet-stream")
	req.Header.Add("Content-Length", strconv.Itoa(len(body)))
	resp, err := http.DefaultClient.Do(req)
	if resp != nil && (resp.StatusCode < 200 || resp.StatusCode >= 300) {
		return nil, fmt.Errorf("HTTP status %d\n", resp.StatusCode)
	}

	defer resp.Body.Close()

	hasher := sha256.New()
	hasher.Write(body)

	return hasher.Sum(nil), nil
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

	plaintextLength := len(b)

	e, err := aesEncrypt(keys[:32], b)
	if err != nil {
		return nil, err
	}

	m := appendMAC(keys[32:], e)

	id, location, err := allocateAttachment()
	if err != nil {
		return nil, err
	}
	digest, err := putAttachment(location, m)
	if err != nil {
		return nil, err
	}

	return &att{id, ct, keys, digest, uint32(plaintextLength)}, nil
}

// ErrInvalidMACForAttachment signals that the downloaded attachment has an invalid MAC.
var ErrInvalidMACForAttachment = errors.New("invalid MAC for attachment")

func handleSingleAttachment(a *textsecure.AttachmentPointer) (*Attachment, error) {
	loc, err := getAttachmentLocation(*a.Id)
	if err != nil {
		return nil, err
	}
	r, err := getAttachment(loc)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	b, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	l := len(b) - 32
	if !verifyMAC(a.Key[32:], b[:l], b[l:]) {
		return nil, ErrInvalidMACForAttachment
	}

	b, err = aesDecrypt(a.Key[:32], b[:l])
	if err != nil {
		return nil, err
	}

	// TODO: verify digest

	return &Attachment{bytes.NewReader(b), a.GetContentType()}, nil
}

func handleAttachments(dm *textsecure.DataMessage) ([]*Attachment, error) {
	atts := dm.GetAttachments()
	if atts == nil {
		return nil, nil
	}

	all := make([]*Attachment, len(atts))
	var err error
	for i, a := range atts {
		all[i], err = handleSingleAttachment(a)
		if err != nil {
			return nil, err
		}
	}
	return all, nil
}
