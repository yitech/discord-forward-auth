package httpapi

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yitech/discord-forward-auth/internal/config"
)

type oauthState struct {
	Nonce  string `json:"n"`
	Return string `json:"r"`
	Host   string `json:"h,omitempty"`
}

func encodeState(returnPath, returnHost string) (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	payload := oauthState{
		Nonce:  base64.RawURLEncoding.EncodeToString(b[:]),
		Return: SafeReturnPath(returnPath),
		Host:   config.NormalizeHost(returnHost),
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func decodeState(raw string, cfg *config.Config) (oauthState, error) {
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
	st.Host = config.NormalizeHost(st.Host)
	if st.Host != "" && !cfg.HostAllowed(st.Host) {
		return st, fmt.Errorf("return host not allowed")
	}
	return st, nil
}
