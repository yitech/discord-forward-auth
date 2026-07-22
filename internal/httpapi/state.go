package httpapi

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

type oauthState struct {
	Nonce  string `json:"n"`
	Return string `json:"r"`
}

func encodeState(returnPath string) (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	payload := oauthState{
		Nonce:  base64.RawURLEncoding.EncodeToString(b[:]),
		Return: SafeReturnPath(returnPath),
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func decodeState(raw string) (oauthState, error) {
	var st oauthState
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return st, fmt.Errorf("invalid state encoding")
	}
	if err := json.Unmarshal(data, &st); err != nil {
		return st, fmt.Errorf("invalid state payload")
	}
	if strings.TrimSpace(st.Nonce) == "" {
		return st, fmt.Errorf("missing state nonce")
	}
	st.Return = SafeReturnPath(st.Return)
	return st, nil
}
