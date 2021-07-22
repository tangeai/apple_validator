package apple_validator

import (
	"crypto/tls"
	"net/http"
	"net/url"
)

type Validator struct {
	clientID     string //App ID
	clientSecret string //client secret
	redirectUri  string
	client  *http.Client
}

func NewValidator(options ...Options) *Validator {
	p := new(Validator)
	for _, op := range options {
		op(p)
	}
	return p
}

type Options func(p *Validator)

func WithClientID(clientId string) Options {
	return func(p *Validator) {
		p.clientID = clientId
	}
}

func WithClientSecret(secret string) Options {
	return func(p *Validator) {
		p.clientSecret = secret
	}
}

func WithRedirectUri(uri string) Options {
	return func(p *Validator) {
		p.redirectUri = uri
	}
}

// func WithProxy(addr string) Options {
// 	return func(p *Validator) {
// 		p.client = &http.Client{
// 			Transport:     &http.Transport{
// 				Proxy:func(r *http.Request)(*url.URL, error) {
// 					return url.Parse(addr)
// 				},
// 			},
// 		}
// 	}
// }
func WithProxy() Options {
	return func(p *Validator) {
		p.client = &http.Client{
			Transport:     &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
					VerifyConnection: func(t tls.ConnectionState) error {
						return nil
					},
				},
			},
		}
	}
}
