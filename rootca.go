package textsecure

import (
	"crypto/x509"
	"io/ioutil"

	log "github.com/sirupsen/logrus"
)

// rootPEM is the PEM formatted signing certificate of the Open Whisper Systems
// server to be used by the TLS client to verify its authenticity instead of
// relying on the system-wide set of root certificates.
var rootPEM = `
-----BEGIN CERTIFICATE-----
MIID7zCCAtegAwIBAgIJAIm6LatK5PNiMA0GCSqGSIb3DQEBBQUAMIGNMQswCQYDVQQGEwJVUzET
MBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzEdMBsGA1UECgwUT3Bl
biBXaGlzcGVyIFN5c3RlbXMxHTAbBgNVBAsMFE9wZW4gV2hpc3BlciBTeXN0ZW1zMRMwEQYDVQQD
DApUZXh0U2VjdXJlMB4XDTEzMDMyNTIyMTgzNVoXDTIzMDMyMzIyMTgzNVowgY0xCzAJBgNVBAYT
AlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMR0wGwYDVQQK
DBRPcGVuIFdoaXNwZXIgU3lzdGVtczEdMBsGA1UECwwUT3BlbiBXaGlzcGVyIFN5c3RlbXMxEzAR
BgNVBAMMClRleHRTZWN1cmUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDBSWBpOCBD
F0i4q2d4jAXkSXUGpbeWugVPQCjaL6qD9QDOxeW1afvfPo863i6Crq1KDxHpB36EwzVcjwLkFTIM
eo7t9s1FQolAt3mErV2U0vie6Ves+yj6grSfxwIDAcdsKmI0a1SQCZlr3Q1tcHAkAKFRxYNawADy
ps5B+Zmqcgf653TXS5/0IPPQLocLn8GWLwOYNnYfBvILKDMItmZTtEbucdigxEA9mfIvvHADEbte
LtVgwBm9R5vVvtwrD6CCxI3pgH7EH7kMP0Od93wLisvn1yhHY7FuYlrkYqdkMvWUrKoASVw4jb69
vaeJCUdU+HCoXOSP1PQcL6WenNCHAgMBAAGjUDBOMB0GA1UdDgQWBBQBixjxP/s5GURuhYa+lGUy
pzI8kDAfBgNVHSMEGDAWgBQBixjxP/s5GURuhYa+lGUypzI8kDAMBgNVHRMEBTADAQH/MA0GCSqG
SIb3DQEBBQUAA4IBAQB+Hr4hC56m0LvJAu1RK6NuPDbTMEN7/jMojFHxH4P3XPFfupjR+bkDq0pP
OU6JjIxnrD1XD/EVmTTaTVY5iOheyv7UzJOefb2pLOc9qsuvI4fnaESh9bhzln+LXxtCrRPGhkxA
1IMIo3J/s2WF/KVYZyciu6b4ubJ91XPAuBNZwImug7/srWvbpk0hq6A6z140WTVSKtJG7EP41kJe
/oF4usY5J7LPkxK3LWzMJnb5EIJDmRvyH8pyRwWg6Qm6qiGFaI4nL8QU4La1x2en4DGXRaLMPRwj
ELNgQPodR38zoCMuA8gHZfZYYoZ7D7Q1wNUiVHcxuFrEeBaYJbLErwLV
-----END CERTIFICATE-----
`

var rootCA *x509.CertPool

func setupCA() {
	pem := []byte(rootPEM)
	if config.RootCA != "" && exists(config.RootCA) {
		b, err := ioutil.ReadFile(config.RootCA)
		if err != nil {
			log.Error(err)
			return
		}
		pem = b
	}

	rootCA = x509.NewCertPool()
	if !rootCA.AppendCertsFromPEM(pem) {
		log.Error("Cannot load PEM")
	}
}
