package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func server() *Server {
	return &Server{
		Name: "test", Version: "v1", Instructions: "be careful",
		Tools: []Tool{
			{
				Name: "echo", Description: "echoes", InputSchema: map[string]any{"type": "object"},
				Handler: func(_ context.Context, args json.RawMessage) (string, error) { return string(args), nil },
			},
			{
				Name: "fail", Description: "fails", InputSchema: map[string]any{"type": "object"},
				Handler: func(context.Context, json.RawMessage) (string, error) { return "", errors.New("nope") },
			},
		},
	}
}

// exchange sends request lines and returns the decoded responses.
func exchange(t *testing.T, lines ...string) []map[string]any {
	t.Helper()
	var out strings.Builder
	if err := server().Serve(context.Background(), strings.NewReader(strings.Join(lines, "\n")+"\n"), &out); err != nil {
		t.Fatal(err)
	}
	var resps []map[string]any
	sc := bufio.NewScanner(strings.NewReader(out.String()))
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("response is not one JSON object per line: %q", sc.Text())
		}
		resps = append(resps, m)
	}
	return resps
}

func result(t *testing.T, resp map[string]any) map[string]any {
	t.Helper()
	r, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result in %v", resp)
	}
	return r
}

func TestHandshakeAndList(t *testing.T) {
	resps := exchange(t,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":"p","method":"ping"}`,
	)
	if len(resps) != 3 {
		t.Fatalf("got %d responses, want 3 (notifications are not answered): %v", len(resps), resps)
	}
	init := result(t, resps[0])
	if init["protocolVersion"] != "2025-03-26" || init["instructions"] != "be careful" {
		t.Errorf("initialize = %v", init)
	}
	if info := init["serverInfo"].(map[string]any); info["name"] != "test" || info["version"] != "v1" {
		t.Errorf("serverInfo = %v", info)
	}
	tools := result(t, resps[1])["tools"].([]any)
	if len(tools) != 2 || tools[0].(map[string]any)["name"] != "echo" || tools[0].(map[string]any)["inputSchema"] == nil {
		t.Errorf("tools/list = %v", tools)
	}
	if resps[2]["id"] != "p" {
		t.Errorf("ping id = %v", resps[2]["id"])
	}
}

func TestInitializeDefaultVersion(t *testing.T) {
	r := result(t, exchange(t, `{"jsonrpc":"2.0","id":1,"method":"initialize"}`)[0])
	if r["protocolVersion"] != DefaultProtocolVersion {
		t.Errorf("protocolVersion = %v", r["protocolVersion"])
	}
}

func TestToolsCall(t *testing.T) {
	resps := exchange(t,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"path":"x"}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo"}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"fail","arguments":{}}}`,
	)
	text := func(r map[string]any) string {
		return r["content"].([]any)[0].(map[string]any)["text"].(string)
	}
	if r := result(t, resps[0]); text(r) != `{"path":"x"}` || r["isError"] != false {
		t.Errorf("echo = %v", r)
	}
	if r := result(t, resps[1]); text(r) != `{}` {
		t.Errorf("missing arguments should become {}: %v", r)
	}
	if r := result(t, resps[2]); text(r) != "nope" || r["isError"] != true {
		t.Errorf("failing tool = %v", r)
	}
}

func TestErrors(t *testing.T) {
	resps := exchange(t,
		`this is not json`,
		`{"jsonrpc":"1.0","id":1,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":2,"method":"resources/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"missing"}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{}}`,
		``,
	)
	wantCodes := []float64{codeParse, codeInvalidRequest, codeMethodNotFound, codeInvalidParams, codeInvalidParams}
	if len(resps) != len(wantCodes) {
		t.Fatalf("got %d responses: %v", len(resps), resps)
	}
	for i, want := range wantCodes {
		e, ok := resps[i]["error"].(map[string]any)
		if !ok || e["code"] != want {
			t.Errorf("response %d = %v, want error code %v", i, resps[i], want)
		}
	}
}

func TestServeStopsOnCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out strings.Builder
	err := server().Serve(ctx, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`+"\n"), &out)
	if !errors.Is(err, context.Canceled) || out.Len() != 0 {
		t.Errorf("err = %v, out = %q", err, out.String())
	}
}
