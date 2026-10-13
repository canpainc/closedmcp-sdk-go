# ClosedMCP Go SDK

A small `net/http` wrapper for the [official Go MCP SDK](https://github.com/modelcontextprotocol/go-sdk). It checks each signed pass, serves protected-resource metadata, and attaches the verified person to the tool's context.

Install with `go get github.com/canpainc/closedmcp-sdk-go@v0.1.1`. The module path is `github.com/canpainc/closedmcp-sdk-go`.

For an existing official `*mcp.Server`, call `closedmcp.NewHandler(existingServer, options)` and serve the returned handler. For an existing mark3labs/mcp-go server, add these imports and wrap its Streamable HTTP handler:

```go
import (
    "log"
    "os"
    "strings"
    closedmcp "github.com/canpainc/closedmcp-sdk-go"
    markserver "github.com/mark3labs/mcp-go/server"
)

httpServer := markserver.NewStreamableHTTPServer(existingServer, markserver.WithStateLess(true))
handler, err := closedmcp.NewHTTPHandler(httpServer, closedmcp.Options{
    Resource: os.Getenv("MCP_URL"),
    AllowedDomains: strings.Split(os.Getenv("ALLOWED_DOMAINS"), ","),
})
if err != nil { log.Fatal(err) }
```

Mount `handler` at your MCP path. `PersonFrom(ctx)` exposes the caller in both frameworks.

## Hello

```go
package main

import (
    "context"
    "log"
    "net/http"
    closedmcp "github.com/canpainc/closedmcp-sdk-go"
    "github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
server := mcp.NewServer(&mcp.Implementation{Name: "hello", Version: "1"}, nil)
mcp.AddTool(server, &mcp.Tool{Name: "hello"},
    func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
        person, _ := closedmcp.PersonFrom(ctx)
        return &mcp.CallToolResult{Content: []mcp.Content{
            &mcp.TextContent{Text: "Hello " + person.Email},
        }}, nil, nil
    })
handler, err := closedmcp.NewHandler(server, closedmcp.Options{
    Resource: "https://example.com/mcp", AllowedDomains: []string{"example.com"},
})
if err != nil { log.Fatal(err) }
log.Fatal(http.ListenAndServe(":8787", handler))
}
```

`Resource` must be the exact public MCP URL registered with ClosedMCP. `AllowedDomains` is required and checks the verified company domain, case insensitively. `PersonFrom(ctx)` gives the current call's `ID`, `Email`, `Company`, `Org`, and optional `AIApp`; it returns `false` outside a verified call. `AIApp` is supplied by the client and is for display only.

Mount the handler directly or in any `net/http` mux. It serves `/.well-known/oauth-protected-resource/mcp` for a `/mcp` resource, plus the generic metadata path. Unauthenticated MCP requests receive `401` with a `WWW-Authenticate` metadata link. The official transport handles stateless Streamable HTTP calls concurrently.

The [runnable template](template/main.go) reads `MCP_URL`, `ALLOWED_DOMAINS` (comma separated), and optional `PORT` (default `8787`). From the repository root, run:

```sh
MCP_URL=https://example.com/mcp ALLOWED_DOMAINS=example.com go run ./template
```

For local integration tests, set `CLOSEDMCP_ORIGIN` and `CLOSEDMCP_JWKS_URL`. By default, passes from `https://closedmcp.com` and the legacy `https://closedmcp.canpai.io` issuer use their respective JWKS endpoints. An explicit issuer accepts only that issuer. The verifier caches keys for five minutes and limits unknown key ID refetches to once every 30 seconds per issuer.

See the [ClosedMCP documentation](https://closedmcp.com/docs).
