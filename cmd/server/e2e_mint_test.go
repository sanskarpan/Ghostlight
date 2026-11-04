package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

func (s *e2eStub) mint(issuer, aud, nonce string) string {
	header := e2eB64(map[string]any{"alg": "RS256", "kid": s.kid, "typ": "JWT"})
	now := time.Now().Unix()
	claims := map[string]any{"iss": issuer, "aud": aud, "sub": "org-a-user",
		"email": "op@acme.test", "name": "Operator", "exp": now + 600, "iat": now, "nonce": nonce}
	input := header + "." + e2eB64(claims)
	digest := crypto.SHA256.New()
	digest.Write([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, digest.Sum(nil))
	if err != nil {
		panic(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func e2eB64(v any) string {
	raw, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(raw)
}

var _ = fmt.Sprintf
