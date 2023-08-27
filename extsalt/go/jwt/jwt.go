package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
