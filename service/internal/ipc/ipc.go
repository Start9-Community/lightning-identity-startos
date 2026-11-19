// Package ipc is the framing the three processes use to talk over unix
// sockets: a 4-byte big-endian length followed by one JSON document, with a
// hard frame cap, a per-connection in-flight cap, and a peer-uid check on
// accept so that only the intended subcontainer can speak to a socket even
// though every subcontainer shares the package's network namespace.
package ipc

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// MaxFrame bounds a single message. Every request this service carries is a
// few KiB at most; the cap is what turns a hostile peer into a closed socket.
const MaxFrame = 8 << 10

// Request is one call from a client.
type Request struct {
	ID     uint64          `json:"id"`
	Type   string          `json:"type"`
	Params json.RawMessage `json:"params,omitempty"`
}

// Response answers one Request.
type Response struct {
	ID     uint64          `json:"id"`
	OK     bool            `json:"ok"`
	Error  string          `json:"error,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
}

// Handler serves one request; returning an error yields an error Response.
type Handler func(ctx context.Context, req Request) (any, error)

func writeFrame(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b) > MaxFrame {
		return fmt.Errorf("ipc: frame of %d bytes exceeds %d", len(b), MaxFrame)
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

func readFrame(r *bufio.Reader, v any) error {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > MaxFrame {
		return fmt.Errorf("ipc: bad frame length %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	return json.Unmarshal(buf, v)
}

// Server accepts connections on a unix socket and dispatches requests.
type Server struct {
	Path        string
	AllowedUIDs []uint32 // empty = any peer (never use that outside tests)
	Mode        os.FileMode
	Handler     Handler
	MaxInFlight int
	Timeout     time.Duration
	Log         *slog.Logger
}

// ListenAndServe creates the socket (replacing a stale file), chmods it and
// serves until ctx ends.
func (s *Server) ListenAndServe(ctx context.Context) error {
	if s.Log == nil {
		s.Log = slog.Default()
	}
	if s.MaxInFlight <= 0 {
		s.MaxInFlight = 32
	}
	if s.Timeout <= 0 {
		s.Timeout = 5 * time.Second
	}
	_ = os.Remove(s.Path)
	ln, err := net.Listen("unix", s.Path)
	if err != nil {
		return err
	}
	defer ln.Close()
	// World-connectable on purpose: the three processes run as unrelated uids
	// with no shared group, and connect() needs write permission on the
	// socket inode. Authorization is the SO_PEERCRED check on accept.
	mode := s.Mode
	if mode == 0 {
		mode = 0o666
	}
	if err := os.Chmod(s.Path, mode); err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		uc, ok := conn.(*net.UnixConn)
		if !ok {
			conn.Close()
			continue
		}
		if !s.peerAllowed(uc) {
			conn.Close()
			continue
		}
		go s.serveConn(ctx, uc)
	}
}

func (s *Server) peerAllowed(c *net.UnixConn) bool {
	if len(s.AllowedUIDs) == 0 {
		return true
	}
	uid, err := PeerUID(c)
	if err != nil {
		s.Log.Warn("ipc: cannot read peer credentials", "err", err)
		return false
	}
	for _, u := range s.AllowedUIDs {
		if u == uid {
			return true
		}
	}
	s.Log.Warn("ipc: rejected peer", "uid", uid, "socket", s.Path)
	return false
}

// PeerUID returns the uid of the process on the other end of a unix socket.
// The lookup is kernel-specific: SO_PEERCRED on Linux (what ships),
// LOCAL_PEERCRED on macOS and the BSDs (so the tests run on a Mac). See
// peercred_*.go.
func PeerUID(c *net.UnixConn) (uint32, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var uid uint32
	var cerr error
	if err := raw.Control(func(fd uintptr) { uid, cerr = peerUID(int(fd)) }); err != nil {
		return 0, err
	}
	return uid, cerr
}

func (s *Server) serveConn(ctx context.Context, c net.Conn) {
	defer c.Close()
	r := bufio.NewReaderSize(c, MaxFrame+4)
	var wmu sync.Mutex
	var inflight int32
	for {
		var req Request
		if err := readFrame(r, &req); err != nil {
			return
		}
		if atomic.AddInt32(&inflight, 1) > int32(s.MaxInFlight) {
			s.Log.Warn("ipc: too many in-flight requests, closing", "socket", s.Path)
			return
		}
		go func(req Request) {
			defer atomic.AddInt32(&inflight, -1)
			rctx, cancel := context.WithTimeout(ctx, s.Timeout)
			defer cancel()
			res := Response{ID: req.ID}
			out, err := s.Handler(rctx, req)
			if err != nil {
				res.Error = err.Error()
			} else {
				b, merr := json.Marshal(out)
				if merr != nil {
					res.Error = merr.Error()
				} else {
					res.OK = true
					res.Result = b
				}
			}
			wmu.Lock()
			defer wmu.Unlock()
			_ = c.SetWriteDeadline(time.Now().Add(s.Timeout))
			if err := writeFrame(c, res); err != nil {
				c.Close()
			}
		}(req)
	}
}

// Client holds one connection to a Server and multiplexes calls on it.
type Client struct {
	Path    string
	Timeout time.Duration

	mu      sync.Mutex
	conn    net.Conn
	reader  *bufio.Reader
	nextID  uint64
	pending map[uint64]chan Response
}

// Call sends one request and waits for its answer, reconnecting as needed.
func (c *Client) Call(ctx context.Context, typ string, params any, out any) error {
	if c.Timeout <= 0 {
		c.Timeout = 5 * time.Second
	}
	var p json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return err
		}
		p = b
	}
	ch, id, err := c.send(Request{Type: typ, Params: p})
	if err != nil {
		return err
	}
	timer := time.NewTimer(c.Timeout)
	defer timer.Stop()
	select {
	case res, ok := <-ch:
		if !ok {
			return errors.New("ipc: connection closed")
		}
		if !res.OK {
			return &RemoteError{Msg: res.Error}
		}
		if out != nil && len(res.Result) > 0 {
			return json.Unmarshal(res.Result, out)
		}
		return nil
	case <-timer.C:
		c.drop(id)
		return errors.New("ipc: timeout")
	case <-ctx.Done():
		c.drop(id)
		return ctx.Err()
	}
}

// RemoteError is an error the server reported for a request.
type RemoteError struct{ Msg string }

func (e *RemoteError) Error() string { return e.Msg }

func (c *Client) send(req Request) (chan Response, uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		d := net.Dialer{Timeout: c.Timeout}
		conn, err := d.Dial("unix", c.Path)
		if err != nil {
			return nil, 0, err
		}
		c.conn = conn
		c.reader = bufio.NewReaderSize(conn, MaxFrame+4)
		c.pending = map[uint64]chan Response{}
		go c.readLoop(conn, c.reader)
	}
	c.nextID++
	req.ID = c.nextID
	ch := make(chan Response, 1)
	c.pending[req.ID] = ch
	_ = c.conn.SetWriteDeadline(time.Now().Add(c.Timeout))
	if err := writeFrame(c.conn, req); err != nil {
		delete(c.pending, req.ID)
		c.closeLocked()
		return nil, 0, err
	}
	return ch, req.ID, nil
}

func (c *Client) drop(id uint64) {
	c.mu.Lock()
	delete(c.pending, id)
	c.mu.Unlock()
}

func (c *Client) closeLocked() {
	if c.conn != nil {
		c.conn.Close()
	}
	c.conn = nil
	for id, ch := range c.pending {
		close(ch)
		delete(c.pending, id)
	}
}

func (c *Client) readLoop(conn net.Conn, r *bufio.Reader) {
	for {
		var res Response
		if err := readFrame(r, &res); err != nil {
			c.mu.Lock()
			if c.conn == conn {
				c.closeLocked()
			}
			c.mu.Unlock()
			return
		}
		c.mu.Lock()
		ch := c.pending[res.ID]
		delete(c.pending, res.ID)
		c.mu.Unlock()
		if ch != nil {
			ch <- res
		}
	}
}

// Close drops the connection.
func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeLocked()
}
