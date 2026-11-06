// Package closedmcp protects an official MCP HTTP server with ClosedMCP passes.
package closedmcp

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const Issuer = "https://closedmcp.com"

const RequiredScope = "mcp:tools"

type Person struct {
	ID      string `json:"id"`
	Email   string `json:"email"`
	Company string `json:"company"`
	Org     string `json:"org"`
	AIApp   string `json:"aiApp,omitempty"`
}

type personKey struct{}

// PersonFrom returns the verified person attached to this MCP request.
func PersonFrom(ctx context.Context) (Person, bool) {
	person, ok := ctx.Value(personKey{}).(Person)
	return person, ok
}

type Options struct {
	Resource       string
	AllowedDomains []string
	Issuer         string // Defaults to the public ClosedMCP issuer.
	JWKSURL        string // Defaults to the selected issuer's JWKS endpoint.
	HTTPClient     *http.Client
}

type Verifier struct {
	resource, issuer, jwksURL string
	allowed                   map[string]bool
	client                    *http.Client
	mu                        sync.Mutex
	keys                      map[string]jose.JSONWebKeySet
	fetched, attempted        map[string]time.Time
}

// NewVerifier validates configuration before accepting requests.
func NewVerifier(opts Options) (*Verifier, error) {
	u, err := url.Parse(opts.Resource)
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return nil, errors.New("resource must be an absolute HTTP(S) MCP URL without query or fragment")
	}
	allowed := make(map[string]bool)
	for _, domain := range opts.AllowedDomains {
		if domain = strings.ToLower(strings.TrimSpace(domain)); domain != "" {
			allowed[domain] = true
		}
	}
	if len(allowed) == 0 {
		return nil, errors.New("allowedDomains must name at least one company")
	}
	issuer := opts.Issuer
	if issuer == "" {
		issuer = Issuer
	}
	jwksURL := opts.JWKSURL
	if jwksURL == "" {
		jwksURL = strings.TrimRight(issuer, "/") + "/.well-known/jwks.json"
	}
	keyURL, err := url.Parse(jwksURL)
	if err != nil || keyURL == nil || (keyURL.Scheme != "http" && keyURL.Scheme != "https") || keyURL.Host == "" {
		return nil, errors.New("jwksUrl must be an absolute HTTP(S) URL")
	}
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &Verifier{resource: opts.Resource, issuer: issuer, jwksURL: jwksURL, allowed: allowed, client: client,
		keys: make(map[string]jose.JSONWebKeySet), fetched: make(map[string]time.Time), attempted: make(map[string]time.Time)}, nil
}

func (v *Verifier) key(ctx context.Context, issuer, kid string) ([]jose.JSONWebKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	set := v.keys[issuer]
	initial := v.fetched[issuer].IsZero() && time.Since(v.attempted[issuer]) >= 30*time.Second
	stale := !v.fetched[issuer].IsZero() && time.Since(v.fetched[issuer]) >= 5*time.Minute && time.Since(v.attempted[issuer]) >= 30*time.Second
	unknown := !v.fetched[issuer].IsZero() && len(set.Key(kid)) == 0 && time.Since(v.attempted[issuer]) >= 30*time.Second
	if initial || stale || unknown {
		v.attempted[issuer] = time.Now()
		jwksURL := v.jwksURL
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
		if err != nil {
			return nil, err
		}
		fetchCtx, cancel := context.WithTimeout(req.Context(), 5*time.Second)
		defer cancel()
		res, err := v.client.Do(req.WithContext(fetchCtx))
		if err != nil {
			return nil, err
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("JWKS returned %d", res.StatusCode)
		}
		var set jose.JSONWebKeySet
		if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&set); err != nil {
			return nil, err
		}
		v.keys[issuer], v.fetched[issuer] = set, time.Now()
		if initial && len(set.Key(kid)) > 0 {
			v.attempted[issuer] = time.Time{}
		}
	}
	set = v.keys[issuer]
	return set.Key(kid), nil
}

type pass struct {
	ClientID string  `json:"client_id"`
	Scope    string  `json:"scope"`
	Email    string  `json:"email"`
	Domain   string  `json:"https://closedmcp.com/claims/domain"`
	Org      string  `json:"https://closedmcp.com/claims/org"`
	Client   *string `json:"https://closedmcp.com/claims/client"`
}

// Verify checks an access token and returns its verified person.
func (v *Verifier) Verify(ctx context.Context, authorization string) (Person, error) {
	fields := strings.Fields(authorization)
	if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") {
		return Person{}, auth.ErrInvalidToken
	}
	info, err := v.verifyToken(ctx, fields[1], nil)
	if err != nil {
		return Person{}, err
	}
	permitted := false
	for _, scope := range info.Scopes {
		if scope == RequiredScope {
			permitted = true
		}
	}
	if !permitted {
		return Person{}, errors.New("insufficient scope")
	}
	return info.Extra["closedMcpPerson"].(Person), nil
}

func (v *Verifier) verifyToken(ctx context.Context, raw string, _ *http.Request) (*auth.TokenInfo, error) {
	token, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil || len(token.Headers) != 1 || token.Headers[0].KeyID == "" {
		return nil, auth.ErrInvalidToken
	}
	typ := token.Headers[0].ExtraHeaders[jose.HeaderType]
	if typ != "at+jwt" && typ != "application/at+jwt" {
		return nil, auth.ErrInvalidToken
	}
	var unverified jwt.Claims
	if err := token.UnsafeClaimsWithoutVerification(&unverified); err != nil || unverified.Issuer != v.issuer {
		return nil, auth.ErrInvalidToken
	}
	keys, err := v.key(ctx, v.issuer, token.Headers[0].KeyID)
	if err != nil {
		return nil, auth.ErrInvalidToken
	}
	for _, key := range keys {
		if _, ok := key.Key.(ed25519.PublicKey); !ok || (key.Algorithm != "" && key.Algorithm != "EdDSA") || (key.Use != "" && key.Use != "sig") {
			continue
		}
		var claims jwt.Claims
		var identity pass
		if err := token.Claims(key.Key, &claims, &identity); err != nil {
			continue
		}
		now := time.Now()
		if claims.Issuer != v.issuer || len(claims.Audience) != 1 || claims.Audience[0] != v.resource || claims.Subject == "" || claims.ID == "" || claims.IssuedAt == nil || claims.Expiry == nil || identity.Email == "" || identity.Domain == "" || identity.Org == "" || identity.ClientID == "" || !v.allowed[strings.ToLower(identity.Domain)] {
			continue
		}
		if err := claims.ValidateWithLeeway(jwt.Expected{Issuer: v.issuer, AnyAudience: jwt.Audience{v.resource}, Time: now}, 0); err != nil {
			continue
		}
		issued, expires := claims.IssuedAt.Time(), claims.Expiry.Time()
		if !expires.After(issued) || expires.Sub(issued) > 5*time.Minute || now.Sub(issued) > 5*time.Minute {
			continue
		}
		person := Person{ID: claims.Subject, Email: identity.Email, Company: identity.Domain, Org: identity.Org}
		if identity.Client != nil {
			person.AIApp = *identity.Client
		}
		return &auth.TokenInfo{Scopes: strings.Fields(identity.Scope), Expiration: expires, UserID: claims.Subject,
			Extra: map[string]any{"closedMcpPerson": person, "client_id": identity.ClientID}}, nil
	}
	return nil, auth.ErrInvalidToken
}

// NewHandler protects every MCP request and serves OAuth protected-resource metadata.
// The supplied server can serve concurrent stateless requests.
func NewHandler(server *mcp.Server, opts Options) (http.Handler, error) {
	if server == nil {
		return nil, errors.New("server is required")
	}
	mcpHandler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{Stateless: true})
	return NewHTTPHandler(mcpHandler, opts)
}

// NewHTTPHandler protects an existing Streamable HTTP handler, including mcp-go.
// The underlying handler receives the verified Person in the request context.
func NewHTTPHandler(mcpHandler http.Handler, opts Options) (http.Handler, error) {
	if mcpHandler == nil {
		return nil, errors.New("handler is required")
	}
	verifier, err := NewVerifier(opts)
	if err != nil {
		return nil, err
	}
	u, _ := url.Parse(opts.Resource)
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	metadataPath := "/.well-known/oauth-protected-resource"
	if path != "/" {
		metadataPath += path
	}
	metadataURL := u.Scheme + "://" + u.Host + metadataPath
	metadata := struct {
		Resource             string   `json:"resource"`
		AuthorizationServers []string `json:"authorization_servers"`
		BearerMethods        []string `json:"bearer_methods_supported"`
		Scopes               []string `json:"scopes_supported"`
	}{opts.Resource, []string{verifier.issuer}, []string{"header"}, []string{RequiredScope}}
	protected := auth.RequireBearerToken(verifier.verifyToken, &auth.RequireBearerTokenOptions{
		ResourceMetadataURL: metadataURL, Scopes: []string{RequiredScope},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		person := auth.TokenInfoFromContext(r.Context()).Extra["closedMcpPerson"].(Person)
		mcpHandler.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), personKey{}, person)))
	}))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && (r.URL.Path == metadataPath || r.URL.Path == "/.well-known/oauth-protected-resource") {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(metadata)
			return
		}
		if r.URL.Path != path {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"error":"not found"}`)
			return
		}
		protected.ServeHTTP(w, r)
	}), nil
}
