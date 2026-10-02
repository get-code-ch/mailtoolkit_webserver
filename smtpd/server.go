// Package smtpd is a minimal receiving SMTP server (RFC 5321) built on the
// standard library. It never relays: every recipient is checked by the
// Backend, which owns the storage.
package smtpd

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"log"
	"net"
	"sync"
	"time"
)

// Mode is the behaviour of a listening port.
type Mode int

const (
	// ModeMX is the public MX port (25): STARTTLS is offered, not required
	// (RFC 3207).
	ModeMX Mode = iota
	// ModeSubmission (587) requires STARTTLS before MAIL.
	ModeSubmission
	// ModeImplicitTLS (465) is TLS from the first byte (RFC 8314).
	ModeImplicitTLS
)

func (m Mode) String() string {
	switch m {
	case ModeSubmission:
		return "submission"
	case ModeImplicitTLS:
		return "smtps"
	default:
		return "mx"
	}
}

// Envelope describes a received message.
type Envelope struct {
	ID         string    `json:"id"`
	Mode       string    `json:"mode"`
	RemoteAddr string    `json:"remote_addr"`
	Helo       string    `json:"helo"`
	MailFrom   string    `json:"mail_from"`
	Recipients []string  `json:"recipients"`
	TLS        bool      `json:"tls"`
	TLSVersion string    `json:"tls_version,omitempty"`
	Received   time.Time `json:"received"`
}

// Backend stores the messages. Addresses are passed in lowercase.
type Backend interface {
	// ValidRecipient reports whether mail for address is accepted.
	ValidRecipient(address string) bool
	// Deliver stores a message for all env.Recipients. data starts with the
	// Received header added by the server.
	Deliver(env Envelope, data []byte) error
}

// Server is a receiving SMTP server. The zero values of the limits get the
// defaults documented on each field.
type Server struct {
	Hostname string
	Backend  Backend
	// TLSConfig enables STARTTLS and ModeImplicitTLS when not nil.
	TLSConfig *tls.Config
	// MaxMessageSize defaults to 25 MB.
	MaxMessageSize int64
	// MaxRecipients defaults to 50.
	MaxRecipients int
	// MaxConnections defaults to 100 simultaneous sessions.
	MaxConnections int
	// Timeout for each command, defaults to 5 minutes (RFC 5321 §4.5.3.2).
	Timeout time.Duration
	// DataTimeout for the whole DATA transfer, defaults to 10 minutes.
	DataTimeout time.Duration
	// MaxErrors before disconnecting a client, defaults to 10.
	MaxErrors int
	Logger    *log.Logger

	initOnce sync.Once
	slots    chan struct{}
}

func (s *Server) init() {
	s.initOnce.Do(func() {
		if s.MaxMessageSize == 0 {
			s.MaxMessageSize = 25 << 20
		}
		if s.MaxRecipients == 0 {
			s.MaxRecipients = 50
		}
		if s.MaxConnections == 0 {
			s.MaxConnections = 100
		}
		if s.Timeout == 0 {
			s.Timeout = 5 * time.Minute
		}
		if s.DataTimeout == 0 {
			s.DataTimeout = 10 * time.Minute
		}
		if s.MaxErrors == 0 {
			s.MaxErrors = 10
		}
		if s.Logger == nil {
			s.Logger = log.Default()
		}
		s.slots = make(chan struct{}, s.MaxConnections)
	})
}

// ListenAndServe listens on addr and serves SMTP in the given mode.
func (s *Server) ListenAndServe(addr string, mode Mode) error {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return s.Serve(l, mode)
}

// Serve accepts connections on l until it is closed.
func (s *Server) Serve(l net.Listener, mode Mode) error {
	s.init()
	if mode == ModeImplicitTLS {
		if s.TLSConfig == nil {
			l.Close()
			return errors.New("smtpd: implicit TLS requires a TLSConfig")
		}
		l = tls.NewListener(l, s.TLSConfig)
	}
	if mode == ModeSubmission && s.TLSConfig == nil {
		l.Close()
		return errors.New("smtpd: submission mode requires a TLSConfig")
	}

	var delay time.Duration
	for {
		conn, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			// Temporary error (e.g. too many open files): back off.
			delay = min(max(2*delay, 5*time.Millisecond), time.Second)
			s.Logger.Printf("smtpd: accept: %v; retrying in %v", err, delay)
			time.Sleep(delay)
			continue
		}
		delay = 0

		select {
		case s.slots <- struct{}{}:
			go func() {
				defer func() { <-s.slots }()
				s.newSession(conn, mode).serve()
			}()
		default:
			conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			conn.Write([]byte("421 4.7.0 Too many connections, try again later\r\n"))
			conn.Close()
		}
	}
}

func newID() string {
	b := make([]byte, 12)
	rand.Read(b)
	return hex.EncodeToString(b)
}
