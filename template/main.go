package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/canpainc/closedmcp-sdk-go"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	resource := os.Getenv("MCP_URL")
	if resource == "" {
		log.Fatal("set MCP_URL to the public MCP URL")
	}
	server := mcp.NewServer(&mcp.Implementation{Name: "hello", Version: "1.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "hello"}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		person, _ := closedmcp.PersonFrom(ctx)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "Hello " + person.Email}}}, nil, nil
	})
	handler, err := closedmcp.NewHandler(server, closedmcp.Options{
		Resource: resource, AllowedDomains: strings.Split(os.Getenv("ALLOWED_DOMAINS"), ","),
		Issuer: os.Getenv("CLOSEDMCP_ORIGIN"), JWKSURL: os.Getenv("CLOSEDMCP_JWKS_URL"),
	})
	if err != nil {
		log.Fatal(err)
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "8787"
	}
	fmt.Println("listening on " + port)
	log.Fatal(http.ListenAndServe(":"+port, handler))
}
