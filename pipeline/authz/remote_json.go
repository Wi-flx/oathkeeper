package authz

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"text/template"
	"time"

	"github.com/pkg/errors"

	"github.com/ory/x/httpx"

	"github.com/ory/oathkeeper/driver/configuration"
	"github.com/ory/oathkeeper/helper"
	"github.com/ory/oathkeeper/pipeline"
	"github.com/ory/oathkeeper/pipeline/authn"
	"github.com/ory/oathkeeper/x"
)

// AuthorizerRemoteJSONConfiguration represents a configuration for the remote_json authorizer.
type AuthorizerRemoteJSONConfiguration struct {
	Remote                           string                                  `json:"remote"`
	Payload                          string                                  `json:"payload"`
	ForwardResponseHeadersToUpstream []string                                `json:"forward_response_headers_to_upstream"`
	Retry                            *AuthorizerRemoteJSONRetryConfiguration `json:"retry"`
}

type AuthorizerRemoteJSONRetryConfiguration struct {
	Timeout string `json:"max_delay"`
	MaxWait string `json:"give_up_after"`
}

// PayloadTemplateID returns a string with which to associate the payload template.
func (c *AuthorizerRemoteJSONConfiguration) PayloadTemplateID() string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(c.Payload)))
}

// AuthorizerRemoteJSON implements the Authorizer interface.
type AuthorizerRemoteJSON struct {
	c configuration.Provider

	client *http.Client
	t      *template.Template
}

// NewAuthorizerRemoteJSON creates a new AuthorizerRemoteJSON.
func NewAuthorizerRemoteJSON(c configuration.Provider) *AuthorizerRemoteJSON {
	return &AuthorizerRemoteJSON{
		c:      c,
		client: httpx.NewResilientClientLatencyToleranceSmall(nil),
		t:      x.NewTemplate("remote_json"),
	}
}

// GetID implements the Authorizer interface.
func (a *AuthorizerRemoteJSON) GetID() string {
	return "remote_json"
}

// Authorize implements the Authorizer interface.
func (a *AuthorizerRemoteJSON) Authorize(r *http.Request, session *authn.AuthenticationSession, config json.RawMessage, _ pipeline.Rule) error {
	c, err := a.Config(config)
	if err != nil {
		return err
	}

	templateID := c.PayloadTemplateID()
	t := a.t.Lookup(templateID)
	if t == nil {
		var err error
		t, err = a.t.New(templateID).Parse(c.Payload)
		if err != nil {
			return errors.WithStack(err)
		}
	}

	var sessionBody bytes.Buffer
	if err := t.Execute(&sessionBody, session); err != nil {
		return errors.WithStack(err)
	}

	var j json.RawMessage
	if err := json.Unmarshal(sessionBody.Bytes(), &j); err != nil {
		return errors.Wrap(err, "payload is not a JSON text")
	}

	var payload interface{}
	if err := json.Unmarshal(sessionBody.Bytes(), &payload); err != nil {
		return errors.Wrap(err, "failed to convert session body to map")
	}

	var body bytes.Buffer
	if bodyMap, ok := payload.(map[string]interface{}); ok {
		var originalRequestCopy bytes.Buffer
		if r.Body != nil {
			if _, err := io.Copy(&originalRequestCopy, r.Body); err != nil {
				return errors.Wrap(err, "failed to clone request body")
			}
		}

		var originalRequest interface{}
		if originalRequestCopy.Len() > 0 {
			if err := json.Unmarshal(originalRequestCopy.Bytes(), &originalRequest); err != nil {
				return errors.Wrap(err, "failed to unmarshal original request")
			}

			if originalRequestMap, ok := originalRequest.(map[string]interface{}); ok {
				for k, v := range originalRequestMap {
					bodyMap[k] = v
				}
			}
		}

		if err := json.NewEncoder(&body).Encode(bodyMap); err != nil {
			return errors.Wrap(err, "failed to build request body")
		}
	} else {
		if err := json.NewEncoder(&body).Encode(payload); err != nil {
			return errors.Wrap(err, "failed to build request body")
		}
	}

	remote, _ := url.Parse(c.Remote)
	reqURL := r.URL
	if reqURL != nil {
		values := remote.Query()
		for k, v := range reqURL.Query() {
			if len(v) > 0 {
				values.Set(k, v[0])
			}
		}
		remote.RawQuery = values.Encode()
	}

	var bodyCompact bytes.Buffer
	if err := json.Compact(&bodyCompact, body.Bytes()); err != nil {
		return errors.Wrap(err, "failed to compact request body")
	}

	req, err := http.NewRequest("POST", remote.String(), &bodyCompact)
	if err != nil {
		return errors.WithStack(err)
	}

	req.Header.Add("Content-Type", "application/json")
	authz := r.Header.Get("Authorization")
	if authz != "" {
		req.Header.Add("Authorization", authz)
	}

	providerId := r.Header.Get("X-Provider-ID")
	if providerId != "" {
		req.Header.Add("X-Provider-ID", providerId)
	}

	res, err := a.client.Do(req.WithContext(r.Context()))
	if err != nil {
		return errors.WithStack(err)
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusForbidden {
		return errors.WithStack(helper.ErrForbidden)
	} else if res.StatusCode != http.StatusOK {
		return errors.Errorf("expected status code %d but got %d", http.StatusOK, res.StatusCode)
	}

	for _, allowedHeader := range c.ForwardResponseHeadersToUpstream {
		session.SetHeader(allowedHeader, res.Header.Get(allowedHeader))
	}

	return nil
}

// Validate implements the Authorizer interface.
func (a *AuthorizerRemoteJSON) Validate(config json.RawMessage) error {
	if !a.c.AuthorizerIsEnabled(a.GetID()) {
		return NewErrAuthorizerNotEnabled(a)
	}

	_, err := a.Config(config)
	return err
}

// Config merges config and the authorizer's configuration and validates the
// resulting configuration. It reports an error if the configuration is invalid.
func (a *AuthorizerRemoteJSON) Config(config json.RawMessage) (*AuthorizerRemoteJSONConfiguration, error) {
	const (
		defaultTimeout = "500ms"
		defaultMaxWait = "1s"
	)
	var c AuthorizerRemoteJSONConfiguration
	if err := a.c.AuthorizerConfig(a.GetID(), config, &c); err != nil {
		return nil, NewErrAuthorizerMisconfigured(a, err)
	}

	if c.ForwardResponseHeadersToUpstream == nil {
		c.ForwardResponseHeadersToUpstream = []string{}
	}

	if c.Retry == nil {
		c.Retry = &AuthorizerRemoteJSONRetryConfiguration{Timeout: defaultTimeout, MaxWait: defaultMaxWait}
	} else {
		if c.Retry.Timeout == "" {
			c.Retry.Timeout = defaultTimeout
		}
		if c.Retry.MaxWait == "" {
			c.Retry.MaxWait = defaultMaxWait
		}
	}
	duration, err := time.ParseDuration(c.Retry.Timeout)
	if err != nil {
		return nil, err
	}

	maxWait, err := time.ParseDuration(c.Retry.MaxWait)
	if err != nil {
		return nil, err
	}
	timeout := time.Millisecond * duration
	a.client = httpx.NewResilientClientLatencyToleranceConfigurable(nil, timeout, maxWait)

	return &c, nil
}
