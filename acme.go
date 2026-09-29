// SPDX-License-Identifier: BSD-3-Clause

package servercert

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

func newManager(a *ACME) (*autocert.Manager, error) {
	if err := cacheDir(a.CacheDir); err != nil {
		return nil, err
	}
	dir := a.DirectoryURL
	if dir == "" {
		dir = acme.LetsEncryptURL
	}
	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(a.CacheDir),
		HostPolicy: autocert.HostWhitelist(a.Domains...),
		Email:      a.Email,
		Client:     &acme.Client{DirectoryURL: dir, HTTPClient: withOrderLocations(a.HTTPClient)},
	}
	if a.EABKeyID != "" {
		key, err := readEABKey(a.EABHMACKeyFile)
		if err != nil {
			return nil, err
		}
		m.ExternalAccountBinding = &acme.ExternalAccountBinding{KID: a.EABKeyID, Key: key}
	}
	if a.HTTPChallenge {
		// autocert tries http-01 only once its HTTPHandler has been asked
		// for; asking now makes the behaviour follow the configuration
		// rather than the order in which the caller wires things up.
		m.HTTPHandler(nil)
	}
	return m, nil
}

// readEABKey reads the EAB HMAC key: base64url as CAs publish it, padded or
// not. Standard base64 is accepted too, since a key pasted through some
// portal or tool may have been re-encoded; the two alphabets cannot be
// confused (a key using both is refused by both decoders).
func readEABKey(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("servercert: EAB HMAC key: %w", err)
	}
	text := strings.TrimRight(strings.TrimSpace(string(raw)), "=")
	if text == "" {
		return nil, fmt.Errorf("servercert: EAB HMAC key file %s is empty", path)
	}
	key, err := base64.RawURLEncoding.DecodeString(text)
	if err != nil {
		var err2 error
		if key, err2 = base64.RawStdEncoding.DecodeString(text); err2 != nil {
			// Deliberately not quoting the text: it is a secret.
			return nil, fmt.Errorf("servercert: EAB HMAC key file %s is not base64url: %w", path, err)
		}
	}
	return key, nil
}

// cacheDir creates dir 0700, or checks that the existing one is a directory
// nobody but its owner can reach: it holds private keys.
func cacheDir(dir string) error {
	fi, err := os.Stat(dir)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("servercert: cache directory: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("servercert: cache directory: %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("servercert: cache directory %s is not a directory", dir)
	}
	return checkPrivate(dir, fi.Mode())
}
