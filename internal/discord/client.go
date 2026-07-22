package discord

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const APIBase = "https://discord.com/api/v10"

var (
	ErrNotGuildMember = errors.New("not a guild member")
	ErrAPI            = errors.New("discord api error")
)

type Client struct {
	HTTP       *http.Client
	ClientID   string
	ClientSecret string
	RedirectURI string
}

func NewClient(clientID, clientSecret, redirectURI string) *Client {
	return &Client{
		HTTP: &http.Client{
			Timeout: 10 * time.Second,
		},
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURI:  redirectURI,
	}
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}

type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
}

type Member struct {
	Roles    []string `json:"roles"`
	Nick     *string  `json:"nick"`
	JoinedAt string   `json:"joined_at"`
	User     *User    `json:"user"`
}

func (c *Client) ExchangeCode(ctx context.Context, code string) (*TokenResponse, error) {
	form := url.Values{}
	form.Set("client_id", c.ClientID)
	form.Set("client_secret", c.ClientSecret)
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", c.RedirectURI)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, APIBase+"/oauth2/token", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: token exchange status %d: %s", ErrAPI, resp.StatusCode, string(body))
	}

	var tok TokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, err
	}
	if tok.AccessToken == "" {
		return nil, fmt.Errorf("%w: empty access token", ErrAPI)
	}
	return &tok, nil
}

func (c *Client) GetMe(ctx context.Context, accessToken string) (*User, error) {
	var user User
	if err := c.getJSON(ctx, accessToken, "/users/@me", &user); err != nil {
		return nil, err
	}
	if user.ID == "" {
		return nil, fmt.Errorf("%w: empty user id", ErrAPI)
	}
	return &user, nil
}

func (c *Client) GetGuildMember(ctx context.Context, accessToken, guildID string) (*Member, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, APIBase+"/users/@me/guilds/"+url.PathEscape(guildID)+"/member", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNotGuildMember
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: guild member status %d: %s", ErrAPI, resp.StatusCode, string(body))
	}

	var member Member
	if err := json.Unmarshal(body, &member); err != nil {
		return nil, err
	}
	return &member, nil
}

func (c *Client) getJSON(ctx context.Context, accessToken, path string, dest any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, APIBase+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: %s status %d: %s", ErrAPI, path, resp.StatusCode, string(body))
	}
	return json.Unmarshal(body, dest)
}

type API interface {
	ExchangeCode(ctx context.Context, code string) (*TokenResponse, error)
	GetMe(ctx context.Context, accessToken string) (*User, error)
	GetGuildMember(ctx context.Context, accessToken, guildID string) (*Member, error)
}
