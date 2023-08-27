package gojwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

type Header struct {
	Type      string `json:"typ"`
	Algorithm string `json:"alg"`
}

type Payload struct {
	Subject  string `json:"sub"`
	Platform string `json:"plt"`
}

func Create(subject string, platform string, secret string) (string, error) {
	inputString := Header{
		Type:      "jwt",
		Algorithm: "HS256",
	}
	headerJson, err := json.Marshal(inputString)
	if err != nil {
		return "", err
	}
	inputBytes := []byte(headerJson)
	encodedString := base64.RawStdEncoding.EncodeToString(inputBytes)
	payload := Payload{
		Subject:  subject,
		Platform: platform,
	}
	payloadJson, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	payloadBytes := []byte(payloadJson)
	payloadEncodedString := base64.RawStdEncoding.EncodeToString(payloadBytes)
	data := fmt.Sprintf("%s.%s", encodedString, payloadEncodedString)
	secretBytes := []byte(secret)
	hasher := hmac.New(sha256.New, secretBytes)
	hasher.Write([]byte(data))
	signature := hasher.Sum(nil)
	signatureHex := hex.EncodeToString(signature)
	jwt := fmt.Sprintf("%s.%s.%s", encodedString, payloadEncodedString, signatureHex)
	return jwt, nil
}

// VerifySignature verifies that jwt is not-tempered and returns Payload
func VerifySignature(jwt string, secret string) (*Payload, error) {
	if len(jwt) == 0 {
		return nil, fmt.Errorf("malformed jwt")
	}
	explodedJwt := strings.Split(jwt, ".")
	if len(explodedJwt) < 3 {
		return nil, fmt.Errorf("malformed jwt")
	}
	data := fmt.Sprintf("%s.%s", explodedJwt[0], explodedJwt[1])
	secretBytes := []byte(secret)
	hasher := hmac.New(sha256.New, secretBytes)
	hasher.Write([]byte(data))
	signature := hasher.Sum(nil)
	signatureHex := hex.EncodeToString(signature)
	if signatureHex == explodedJwt[2] {
		var p Payload
		payload, err := base64.RawStdEncoding.DecodeString(explodedJwt[1])
		err = json.Unmarshal(payload, &p)
		return &p, err
	}
	return nil, fmt.Errorf("signature failed")
}
