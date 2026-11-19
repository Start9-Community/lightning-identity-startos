package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRoundTripAndErrors(t *testing.T) {
	sock := filepath.Join(shortTempDir(t), "t.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := &Server{Path: sock, AllowedUIDs: []uint32{uint32(os.Getuid())}, Handler: func(ctx context.Context, req Request) (any, error) {
		switch req.Type {
		case "echo":
			var p map[string]string
			_ = json.Unmarshal(req.Params, &p)
			return p, nil
		case "slow":
			time.Sleep(200 * time.Millisecond)
			return "late", nil
		default:
			return nil, errors.New("nope")
		}
	}}
	go srv.ListenAndServe(ctx)
	time.Sleep(50 * time.Millisecond)

	c := &Client{Path: sock, Timeout: 2 * time.Second}
	var out map[string]string
	if err := c.Call(ctx, "echo", map[string]string{"a": "b"}, &out); err != nil || out["a"] != "b" {
		t.Fatalf("echo: %v %v", err, out)
	}
	err := c.Call(ctx, "missing", nil, nil)
	var re *RemoteError
	if !errors.As(err, &re) || re.Msg != "nope" {
		t.Fatalf("expected remote error, got %v", err)
	}
	// concurrent calls multiplex on one connection
	done := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			var s string
			done <- c.Call(ctx, "slow", nil, &s)
		}()
	}
	for i := 0; i < 2; i++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}

func TestFrameCap(t *testing.T) {
	sock := filepath.Join(shortTempDir(t), "t.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := &Server{Path: sock, Handler: func(ctx context.Context, req Request) (any, error) { return "ok", nil }}
	go srv.ListenAndServe(ctx)
	time.Sleep(50 * time.Millisecond)
	c := &Client{Path: sock, Timeout: time.Second}
	big := strings.Repeat("x", MaxFrame)
	if err := c.Call(ctx, "x", map[string]string{"p": big}, nil); err == nil {
		t.Fatal("oversized frame should fail")
	}
}

func TestPeerUIDRejected(t *testing.T) {
	sock := filepath.Join(shortTempDir(t), "t.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := &Server{Path: sock, AllowedUIDs: []uint32{uint32(os.Getuid()) + 12345}, Handler: func(ctx context.Context, req Request) (any, error) { return "ok", nil }}
	go srv.ListenAndServe(ctx)
	time.Sleep(50 * time.Millisecond)
	c := &Client{Path: sock, Timeout: 500 * time.Millisecond}
	if err := c.Call(ctx, "x", nil, nil); err == nil {
		t.Fatal("call from a disallowed uid should fail")
	}
}

// shortTempDir is for unix sockets: their path is capped at 104 bytes on
// macOS (108 on Linux) and t.TempDir() on a Mac is longer than that.
func shortTempDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "li")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}
