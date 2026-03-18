// Copyright (c) 2026 Ggroup
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package core

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"gr3m/key"
	"math/big"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
)

const ProtocolVersion = "GR3M-v1-SECURE"

type SessionResult struct {
	EncryptionKey []byte
}

func PerformHandshake(conn net.Conn, isServer bool, expectedPubKey string, staticPriv []byte) (*SessionResult, error) {
	if isServer {
		cert, err := generateSelfSignedCert()
		if err != nil {
			return nil, err
		}

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
		tlsConn := tls.Server(conn, tlsConfig)
		if err := tlsConn.Handshake(); err != nil {
			return nil, err
		}
		return secureExchange(tlsConn, true, "", staticPriv)
	}

	config := &utls.Config{ServerName: "google.com", InsecureSkipVerify: true}
	uConn := utls.UClient(conn, config, utls.HelloChrome_Auto)
	if err := uConn.Handshake(); err != nil {
		return nil, err
	}
	return secureExchange(uConn, false, expectedPubKey, nil)
}

func secureExchange(conn net.Conn, isServer bool, expectedPubKey string, staticPriv []byte) (*SessionResult, error) {
	var priv [32]byte
	var pub [32]byte
	var err error

	if isServer && staticPriv != nil {
		copy(priv[:], staticPriv)
		pub = key.GetPublicFromPrivate(priv)
	} else {
		priv, err, pub = key.GenPrvKeyAndPublic()
		if err != nil {
			return nil, err
		}
	}

	var theirPub [32]byte
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	if isServer {
		buf := make([]byte, 512)
		n, err := conn.Read(buf)
		if err != nil || n < 32 {
			return nil, errors.New("handshake read failed")
		}
		copy(theirPub[:], buf[n-32:])
		conn.Write(pub[:])
	} else {
		payload := append([]byte(ProtocolVersion), pub[:]...)
		if _, err := conn.Write(payload); err != nil {
			return nil, err
		}

		buf := make([]byte, 32)
		if _, err := conn.Read(buf); err != nil {
			return nil, err
		}
		copy(theirPub[:], buf)

		if expectedPubKey != "" {
			hash := sha256.Sum256(theirPub[:])
			if hex.EncodeToString(hash[:]) != expectedPubKey {
				return nil, errors.New("identity mismatch")
			}
		}
	}

	conn.SetDeadline(time.Time{})

	shared, _ := key.GenSecretKey(theirPub, priv)
	hasher := sha256.New()
	hasher.Write(shared[:])
	return &SessionResult{EncryptionKey: hasher.Sum(nil)}, nil
}

func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Google Inc."},
			CommonName:   "google.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	privBytes, _ := x509.MarshalECPrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	return tls.X509KeyPair(certPEM, keyPEM)
}
