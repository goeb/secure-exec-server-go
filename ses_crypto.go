package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
)

type publicKey struct {
	key crypto.PublicKey
	filename string
}

func getSignatureFromFirstLine(script []byte) (signature, payload []byte, err error) {
	if len(script) < 2 {
		return []byte{}, []byte{}, errors.New("too short")
	}
	if script[0] != '#' {
		return []byte{}, []byte{}, errors.New("missing '#' as first character")
	}
	script = script[1:] // skip #

	// Skip SPACE characters
	for len(script) >= 1 && script[0] == byte(' ') {
		script = script[1:]
	}
	if len(script) == 0 {
		return []byte{}, []byte{}, errors.New("missing signature line")
	}

	sighex := script[:]
	sighex_len := 0
	// Get the first '\n' that marks the end of the first line
	for len(script) >= 1 && script[0] != byte('\n') {
		script = script[1:]
		sighex_len++
	}
	if len(script) == 0 {
		return []byte{}, []byte{}, errors.New("missing LF character at end of signature line")
	}

	sighex = sighex[:sighex_len]
	sig, err := hex.DecodeString(string(sighex))
	if err != nil {
		return []byte{}, []byte{}, err
	}
	script = script[1:] // skip past the '\n'
	return sig, script, nil
}

/* Authenticate a script
 *
 * @param script
 * @param pubkeys   List of available public keys
 *
 * @return          Filename that authenticates the script, or error
 *
 * The first line of the script must contain the signature in the format:
 *   "#" <spaces> <hexadecimal dump> "\n"
 * The payload is everything that follows, and is verified.
 */
func authenticateScript(script []byte, pubkeys []publicKey) (string, error) {
	signature, payload, err := getSignatureFromFirstLine(script);
	if err != nil {
		return "", err
	}

	// Try all public keys in a row
	for _, pubkey := range pubkeys {
		verified := verify(payload, pubkey.key, signature)
		if verified {
			return pubkey.filename, nil
		}
		// Else, try next public key in list
	}
	return "", errors.New("verification failed")
}

/*
 * Verify a message against a public key and a signature
 */
func verify(payload []byte, pubkey crypto.PublicKey, signature []byte) (bool) {
	hash := sha256.Sum256(payload)
	// TODO: accept other keys than ECDSA: RSA, ...
	ecdsaPubkey := pubkey.(*ecdsa.PublicKey)
	valid := ecdsa.VerifyASN1(ecdsaPubkey, hash[:], signature)
	return valid
}

/*
 * Get the public key of X509 certificate (PEM encoded)
 *
 */
func loadPublicKey(certpath string) (publicKey, error) {
	pubkey := publicKey{}

	contents, err := os.ReadFile(certpath)
	if err != nil {
		return publicKey{}, err
	}

	block, _ := pem.Decode(contents)
	if block == nil {
		return publicKey{}, errors.New("Cannot decode PEM")
	}

	var cert *x509.Certificate
	cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return publicKey{}, err
	}

	if cert.KeyUsage & x509.KeyUsageDigitalSignature != 1 {
		INFO("Key usage 0x%x does not have digitalSignature. Ignoring certificate: %s\n", cert.KeyUsage, certpath)
		return publicKey{}, nil
	}

	pubkey.key = cert.PublicKey
	pubkey.filename = certpath

	return pubkey, nil
}
