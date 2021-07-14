package oidc

import (
	"context"
	"fmt"
	"net/url"

	"github.com/pkg/errors"
	"golang.org/x/oauth2"

	"github.com/ory/herodot"
	"github.com/ory/x/stringslice"

	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	gooidc "github.com/coreos/go-oidc"
)

var _ Provider = new(ProviderLine)

type ProviderLine struct {
	p      *gooidc.Provider
	config *Configuration
	public *url.URL
}

func NewProviderLine(
	config *Configuration,
	public *url.URL,
) *ProviderLine {
	return &ProviderLine{
		config: config,
		public: public,
	}
}

func (g *ProviderLine) Config() *Configuration {
	return g.config
}

func (g *ProviderLine) provider(ctx context.Context) (*gooidc.Provider, error) {
	if g.p == nil {
		p, err := gooidc.NewProvider(ctx, g.config.IssuerURL)
		if err != nil {
			return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("Unable to initialize OpenID Connect Provider: %s", err))
		}
		g.p = p
	}
	return g.p, nil
}

func (g *ProviderLine) oauth2ConfigFromEndpoint(endpoint oauth2.Endpoint) *oauth2.Config {
	scope := g.config.Scope
	if !stringslice.Has(scope, gooidc.ScopeOpenID) {
		scope = append(scope, gooidc.ScopeOpenID)
	}

	return &oauth2.Config{
		ClientID:     g.config.ClientID,
		ClientSecret: g.config.ClientSecret,
		Endpoint:     endpoint,
		Scopes:       scope,
		RedirectURL:  g.config.Redir(g.public),
	}
}

func (g *ProviderLine) OAuth2(ctx context.Context) (*oauth2.Config, error) {
	p, err := g.provider(ctx)
	if err != nil {
		return nil, err
	}

	endpoint := p.Endpoint()

	return g.oauth2ConfigFromEndpoint(endpoint), nil
}

func (g *ProviderLine) AuthCodeURLOptions(r ider) []oauth2.AuthCodeOption {
	var options []oauth2.AuthCodeOption

	if isForced(r) {
		options = append(options, oauth2.SetAuthURLParam("prompt", "login"))
	}
	if len(g.config.RequestedClaims) != 0 {
		options = append(options, oauth2.SetAuthURLParam("claims", string(g.config.RequestedClaims)))
	}

	return options
}

// func (g *ProviderLine) verifyAndDecodeClaimsWithProvider(ctx context.Context, provider *gooidc.Provider, raw string) (*Claims, error) {
// 	token, err := provider.
// 		Verifier(&gooidc.Config{
// 			ClientID:             g.config.ClientID,
// 			SupportedSigningAlgs: []string{"HS256"},
// 		}).
// 		Verify(ctx, raw)
// 	if err != nil {
// 		return nil, errors.WithStack(herodot.ErrBadRequest.WithReasonf("%s", err))
// 	}

// 	var claims Claims
// 	if err := token.Claims(&claims); err != nil {
// 		return nil, errors.WithStack(herodot.ErrBadRequest.WithReasonf("%s", err))
// 	}

// 	return &claims, nil
// }

func (g *ProviderLine) Claims(ctx context.Context, exchange *oauth2.Token) (*Claims, error) {
	raw, ok := exchange.Extra("id_token").(string)
	if !ok || len(raw) == 0 {
		return nil, errors.WithStack(ErrIDTokenMissing)
	}

	p, err := g.provider(ctx)
	if err != nil {
		return nil, err
	}

	// return g.verifyAndDecodeClaimsWithProvider(ctx, p, raw)
	return decodeClaims(p, raw)
}

func decodeClaims(p *gooidc.Provider, idTokenRaw string) (*Claims, error) {
	// fmt.Printf("idtokenraw %#v", idTokenRaw)
	payload, err := parseJWT(idTokenRaw)
	if err != nil {
		return nil, fmt.Errorf("oidc: malformed jwt: %v", err)
	}
	var idToken idToken
	// fmt.Printf("payload %#v", payload)
	if err := json.Unmarshal(payload, &idToken); err != nil {
		return nil, fmt.Errorf("oidc: failed to unmarshal claims: %v", err)
	}

	distributedClaims := make(map[string]claimSource)
	// fmt.Printf("qwertyuio")
	//step through the token to map claim names to claim sources"
	for cn, src := range idToken.ClaimNames {
		if src == "" {
			return nil, fmt.Errorf("oidc: failed to obtain source from claim name")
		}
		s, ok := idToken.ClaimSources[src]
		if !ok {
			return nil, fmt.Errorf("oidc: source does not exist")
		}
		distributedClaims[cn] = s
	}

	token := &MyIDToken{
		// IDToken: &gooidc.IDToken{
		// 	Issuer:          idToken.Issuer,
		// 	Subject:         idToken.Subject,
		// 	Audience:        []string(idToken.Audience),
		// 	Expiry:          time.Time(idToken.Expiry),
		// 	IssuedAt:        time.Time(idToken.IssuedAt),
		// 	Nonce:           idToken.Nonce,
		// 	AccessTokenHash: idToken.AtHash,
		// },
		claims: payload,
		// distributedClaims: distributedClaims,
	}

	var claims Claims
	if err := token.Claims(&claims); err != nil {
		return nil, errors.WithStack(herodot.ErrBadRequest.WithReasonf("%s", err))
	}
	fmt.Printf("claims %#v", claims)
	return &claims, nil
}

func (i MyIDToken) Claims(v interface{}) error {
	if i.claims == nil {
		return errors.New("oidc: claims not set")
	}
	return json.Unmarshal(i.claims, v)
}

func parseJWT(p string) ([]byte, error) {
	parts := strings.Split(p, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("oidc: malformed jwt, expected 3 parts got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("oidc: malformed jwt payload: %v", err)
	}
	return payload, nil
}

type MyIDToken struct {
	// *gooidc.IDToken
	claims []byte
	// distributedClaims map[string]claimSource
}

type idToken struct {
	Issuer       string                 `json:"iss"`
	Subject      string                 `json:"sub"`
	Audience     audience               `json:"aud"`
	Expiry       jsonTime               `json:"exp"`
	IssuedAt     jsonTime               `json:"iat"`
	NotBefore    *jsonTime              `json:"nbf"`
	Nonce        string                 `json:"nonce"`
	AtHash       string                 `json:"at_hash"`
	ClaimNames   map[string]string      `json:"_claim_names"`
	ClaimSources map[string]claimSource `json:"_claim_sources"`
}

type claimSource struct {
	Endpoint    string `json:"endpoint"`
	AccessToken string `json:"access_token"`
}

type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		*a = audience{s}
		return nil
	}
	var auds []string
	if err := json.Unmarshal(b, &auds); err != nil {
		return err
	}
	*a = audience(auds)
	return nil
}

type jsonTime time.Time

func (j *jsonTime) UnmarshalJSON(b []byte) error {
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	var unix int64

	if t, err := n.Int64(); err == nil {
		unix = t
	} else {
		f, err := n.Float64()
		if err != nil {
			return err
		}
		unix = int64(f)
	}
	*j = jsonTime(time.Unix(unix, 0))
	return nil
}
