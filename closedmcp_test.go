package closedmcp_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/canpainc/closedmcp-sdk-go"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	markmcp "github.com/mark3labs/mcp-go/mcp"
	markserver "github.com/mark3labs/mcp-go/server"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var (
	emailOne = strings.Join([]string{"user1", "example.com"}, "@")
	emailTwo = strings.Join([]string{"user2", "example.com"}, "@")
)

type fixture struct {
	private          ed25519.PrivateKey
	jwks             *httptest.Server
	issuer, resource string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := jose.JSONWebKey{Key: public, KeyID: "test-key", Algorithm: "EdDSA", Use: "sig"}
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key}})
	}))
	t.Cleanup(jwks.Close)
	return &fixture{private: private, jwks: jwks, issuer: "https://issuer.example", resource: "https://example.com/mcp"}
}

func (f *fixture) options() closedmcp.Options {
	return closedmcp.Options{Resource: f.resource, AllowedDomains: []string{" Example.COM "}, Issuer: f.issuer, JWKSURL: f.jwks.URL}
}

func (f *fixture) token(t *testing.T, changes map[string]any, private ed25519.PrivateKey) string {
	return f.tokenKID(t, changes, private, "test-key")
}

func (f *fixture) tokenKID(t *testing.T, changes map[string]any, private ed25519.PrivateKey, kid string) string {
	t.Helper()
	if private == nil {
		private = f.private
	}
	now := time.Now().Unix()
	claims := map[string]any{"iss": f.issuer, "aud": f.resource, "sub": "person-123", "email": emailOne, "domain": "example.com", "org": "acme", "client": "Test app", "iat": now, "exp": now + 300, "jti": "pass-123"}
	for k, v := range changes {
		if v == nil {
			delete(claims, k)
		} else {
			claims[k] = v
		}
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: jose.JSONWebKey{Key: private, KeyID: kid}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestDefaultIssuers(t *testing.T) {
	f := newFixture(t)
	var requested []string
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		requested = append(requested, r.URL.String())
		copy := r.Clone(r.Context())
		copy.URL.Scheme, copy.URL.Host = "http", strings.TrimPrefix(f.jwks.URL, "http://")
		return http.DefaultTransport.RoundTrip(copy)
	})}
	opts := f.options()
	opts.Issuer, opts.JWKSURL, opts.HTTPClient = "", "", client
	v, err := closedmcp.NewVerifier(opts)
	if err != nil {
		t.Fatal(err)
	}
	for _, issuer := range []string{closedmcp.Issuer, "https://closedmcp.canpai.io"} {
		if _, err := v.Verify(context.Background(), "Bearer "+f.token(t, map[string]any{"iss": issuer}, nil)); err != nil {
			t.Fatal(err)
		}
	}
	if len(requested) != 2 || requested[0] != closedmcp.Issuer+"/.well-known/jwks.json" || requested[1] != "https://closedmcp.canpai.io/.well-known/jwks.json" {
		t.Fatalf("JWKS requests = %v", requested)
	}
	if _, err := v.Verify(context.Background(), "Bearer "+f.token(t, map[string]any{"iss": "https://other.example"}, nil)); err == nil {
		t.Fatal("accepted other issuer")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestUnknownKIDCooldown(t *testing.T) {
	f := newFixture(t)
	requests := 0
	opts := f.options()
	opts.HTTPClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		requests++
		return http.DefaultTransport.RoundTrip(r)
	})}
	v, err := closedmcp.NewVerifier(opts)
	if err != nil {
		t.Fatal(err)
	}
	valid := "Bearer " + f.token(t, nil, nil)
	if _, err := v.Verify(context.Background(), valid); err != nil {
		t.Fatal(err)
	}
	unknown := "Bearer " + f.tokenKID(t, nil, nil, "new-key")
	for range 3 {
		if _, err := v.Verify(context.Background(), unknown); err == nil {
			t.Fatal("accepted unknown key")
		}
	}
	if requests != 2 {
		t.Fatalf("JWKS requests = %d, want 2", requests)
	}
}

func TestVerifier(t *testing.T) {
	f := newFixture(t)
	verifier, err := closedmcp.NewVerifier(f.options())
	if err != nil {
		t.Fatal(err)
	}
	person, err := verifier.Verify(context.Background(), "Bearer "+f.token(t, nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	if person != (closedmcp.Person{ID: "person-123", Email: emailOne, Company: "example.com", Org: "acme", AIApp: "Test app"}) {
		t.Fatalf("person = %+v", person)
	}
	_, badPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	cases := map[string]string{
		"missing": "", "wrong audience": f.token(t, map[string]any{"aud": "https://other.example/mcp"}, nil),
		"multiple audiences": f.token(t, map[string]any{"aud": []string{f.resource, "https://other.example/mcp"}}, nil),
		"expired":            f.token(t, map[string]any{"iat": now - 601, "exp": now - 301}, nil),
		"overlong":           f.token(t, map[string]any{"exp": now + 301}, nil),
		"disallowed company": f.token(t, map[string]any{"domain": "other.example"}, nil),
		"bad signature":      f.token(t, nil, badPrivate),
		"missing email":      f.token(t, map[string]any{"email": nil}, nil),
		"missing id":         f.token(t, map[string]any{"jti": nil}, nil),
		"wrong issuer":       f.token(t, map[string]any{"iss": closedmcp.Issuer}, nil),
		"future issue":       f.token(t, map[string]any{"iat": now + 300, "exp": now + 600}, nil),
	}
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := verifier.Verify(context.Background(), "Bearer "+token); err == nil {
				t.Fatal("accepted invalid pass")
			}
		})
	}
	opts := f.options()
	opts.AllowedDomains = nil
	if _, err := closedmcp.NewVerifier(opts); err == nil {
		t.Fatal("accepted empty allowlist")
	}
	if _, ok := closedmcp.PersonFrom(context.Background()); ok {
		t.Fatal("person outside request")
	}
}

func call(t *testing.T, client *http.Client, base, token, method, params string, id int) (int, map[string]any, http.Header) {
	t.Helper()
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":%q,"params":%s}`, id, method, params)
	req, err := http.NewRequest(http.MethodPost, base+"/mcp", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	data, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(string(data), "event:") {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "data: ") {
				data = []byte(strings.TrimPrefix(line, "data: "))
				break
			}
		}
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("status %d body %q: %v", res.StatusCode, data, err)
	}
	return res.StatusCode, decoded, res.Header
}

func resultText(t *testing.T, body map[string]any) string {
	t.Helper()
	result, ok := body["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result: %+v", body)
	}
	content, ok := result["content"].([]any)
	if !ok || len(content) == 0 {
		t.Fatalf("no content: %+v", body)
	}
	return content[0].(map[string]any)["text"].(string)
}

func TestHandlerAndConcurrentPeople(t *testing.T) {
	f := newFixture(t)
	server := mcp.NewServer(&mcp.Implementation{Name: "hello", Version: "1.0.0"}, nil)
	var ready sync.WaitGroup
	ready.Add(2)
	release := make(chan struct{})
	mcp.AddTool(server, &mcp.Tool{Name: "hello"}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		person, ok := closedmcp.PersonFrom(ctx)
		if !ok {
			return nil, nil, fmt.Errorf("missing person")
		}
		ready.Done()
		<-release
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: person.Email}}}, nil, nil
	})
	handler, err := closedmcp.NewHandler(server, f.options())
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(handler)
	defer httpServer.Close()
	res, err := http.Get(httpServer.URL + "/.well-known/oauth-protected-resource/mcp")
	if err != nil {
		t.Fatal(err)
	}
	var metadata map[string]any
	if err := json.NewDecoder(res.Body).Decode(&metadata); err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 200 || metadata["resource"] != f.resource || metadata["authorization_servers"].([]any)[0] != f.issuer {
		t.Fatalf("metadata = %+v", metadata)
	}
	status, _, headers := call(t, httpServer.Client(), httpServer.URL, "", "initialize", `{}`, 1)
	if status != 401 || headers.Get("WWW-Authenticate") != `Bearer resource_metadata="https://example.com/.well-known/oauth-protected-resource/mcp"` {
		t.Fatalf("missing pass: %d %+v", status, headers)
	}
	type answer struct {
		text   string
		status int
	}
	answers := make(chan answer, 2)
	for i, email := range []string{emailOne, emailTwo} {
		go func(i int, email string) {
			token := f.token(t, map[string]any{"sub": fmt.Sprintf("person-%d", i), "email": email}, nil)
			status, body, _ := call(t, httpServer.Client(), httpServer.URL, token, "tools/call", `{"name":"hello","arguments":{}}`, i+2)
			answers <- answer{resultText(t, body), status}
		}(i, email)
	}
	done := make(chan struct{})
	go func() { ready.Wait(); close(done) }()
	select {
	case <-done:
		close(release)
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("calls did not run concurrently")
	}
	seen := map[string]bool{}
	for range 2 {
		a := <-answers
		if a.status != 200 {
			t.Fatalf("status %d", a.status)
		}
		seen[a.text] = true
	}
	if !seen[emailOne] || !seen[emailTwo] {
		t.Fatalf("people = %+v", seen)
	}
}

func TestMcpGoExistingServer(t *testing.T) {
	f := newFixture(t)
	server := markserver.NewMCPServer("hello", "1.0.0")
	server.AddTool(markmcp.NewTool("hello"), func(ctx context.Context, _ markmcp.CallToolRequest) (*markmcp.CallToolResult, error) {
		person, ok := closedmcp.PersonFrom(ctx)
		if !ok {
			return nil, fmt.Errorf("missing verified person")
		}
		return markmcp.NewToolResultText("Hello " + person.Email), nil
	})
	handler, err := closedmcp.NewHTTPHandler(markserver.NewStreamableHTTPServer(server, markserver.WithStateLess(true)), f.options())
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(handler)
	defer httpServer.Close()
	status, _, _ := call(t, httpServer.Client(), httpServer.URL, "", "tools/list", `{}`, 1)
	if status != 401 {
		t.Fatalf("missing pass: %d", status)
	}
	status, answer, _ := call(t, httpServer.Client(), httpServer.URL, f.token(t, nil, nil), "tools/call", `{"name":"hello","arguments":{}}`, 2)
	if status != 200 || resultText(t, answer) != "Hello "+emailOne {
		t.Fatalf("call: %d %+v", status, answer)
	}
}

func TestTemplateRealMCPCall(t *testing.T) {
	f := newFixture(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	f.resource = base + "/mcp"
	binary := filepath.Join(t.TempDir(), "hello")
	build := exec.Command("go", "build", "-o", binary, "./template")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build template: %v: %s", err, out)
	}
	cmd := exec.Command(binary)
	cmd.Env = append(os.Environ(), "MCP_URL="+f.resource, "ALLOWED_DOMAINS=example.com", fmt.Sprintf("PORT=%d", port), "CLOSEDMCP_ORIGIN="+f.issuer, "CLOSEDMCP_JWKS_URL="+f.jwks.URL)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	client := &http.Client{Timeout: 5 * time.Second}
	var res *http.Response
	for range 100 {
		res, err = client.Get(base + "/.well-known/oauth-protected-resource/mcp")
		if err == nil {
			res.Body.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("template did not start: %v", err)
	}
	token := f.token(t, nil, nil)
	status, initialized, _ := call(t, client, base, token, "initialize", `{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}`, 1)
	if status != 200 || initialized["result"].(map[string]any)["serverInfo"].(map[string]any)["name"] != "hello" {
		t.Fatalf("initialize: %d %+v", status, initialized)
	}
	status, listed, _ := call(t, client, base, token, "tools/list", `{}`, 2)
	if status != 200 || listed["result"].(map[string]any)["tools"].([]any)[0].(map[string]any)["name"] != "hello" {
		t.Fatalf("tools/list: %d %+v", status, listed)
	}
	status, answer, _ := call(t, client, base, token, "tools/call", `{"name":"hello","arguments":{}}`, 3)
	if status != 200 || resultText(t, answer) != "Hello "+emailOne {
		t.Fatalf("call: %d %+v", status, answer)
	}
}
