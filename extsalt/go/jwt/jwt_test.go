package jwt

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestCreateJWT(t *testing.T) {
	sub := "12123"
	plt := "web"
	secret := "some secret"
	jwt, err := Create(sub, plt, secret)
	if err != nil {
		t.Error(err)
	}
	explodedJwt := strings.Split(jwt, ".")
	if len(explodedJwt) != 3 {
		t.Error("Invalid jwt")
	}
	header, err := base64.RawStdEncoding.DecodeString(explodedJwt[0])
	if err != nil {
		t.Error(err)
	}
	var h Header
	err = json.Unmarshal(header, &h)
	if err != nil {
		t.Error(err)
	}
	if h.Algorithm != "HS256" {
		t.Error("invalid algo")
	}
	if h.Type != "jwt" {
		t.Error("invalid token type")
	}
	var p Payload
	payload, err := base64.RawStdEncoding.DecodeString(explodedJwt[1])
	err = json.Unmarshal(payload, &p)
	if p.Platform != plt {
		t.Error("invalid plt")
	}
	if p.Subject != sub {
		t.Error("invalid sub")
	}
	_, err = base64.RawStdEncoding.DecodeString(explodedJwt[2])
	if err != nil {
		t.Error(err)
	}
}
