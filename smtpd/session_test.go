package smtpd

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net"
	"net/smtp"
	"net/textproto"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/get-code-ch/mailtoolkit_webserver/internal/testcert"
)

type delivery struct {
	env  Envelope
	data []byte
}

type fakeBackend struct {
	valid map[string]bool

	mu        sync.Mutex
	delivered []delivery
}

func (b *fakeBackend) ValidRecipient(address string) bool { return b.valid[address] }

func (b *fakeBackend) Deliver(env Envelope, data []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.delivered = append(b.delivered, delivery{env, append([]byte(nil), data...)})
	return nil
}

func (b *fakeBackend) deliveries() []delivery {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]delivery(nil), b.delivered...)
}

type testServer struct {
	addr    string
	backend *fakeBackend
	roots   *x509.CertPool
}

// start runs a server on a random local port. configure may change the
// server before it starts.
func start(t *testing.T, mode Mode, withTLS bool, configure func(*Server)) *testServer {
	t.Helper()
	backend := &fakeBackend{valid: map[string]bool{"box@example.test": true, "other@example.test": true}}
	srv := &Server{Hostname: "mx.example.test", Backend: backend, Logger: log.New(io.Discard, "", 0)}
	ts := &testServer{backend: backend}
	if withTLS {
		certPEM, _, cert := testcert.Generate(t, "mx.example.test")
		srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
		ts.roots = x509.NewCertPool()
		ts.roots.AppendCertsFromPEM(certPEM)
	}
	if configure != nil {
		configure(srv)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go srv.Serve(l, mode)
	ts.addr = l.Addr().String()
	return ts
}

func (ts *testServer) clientTLS() *tls.Config {
	return &tls.Config{RootCAs: ts.roots, ServerName: "mx.example.test"}
}

// raw is a line level SMTP client to test protocol details net/smtp hides.
type raw struct {
	t    *testing.T
	conn net.Conn
	text *textproto.Conn
}

func dialRaw(t *testing.T, addr string) *raw {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	r := &raw{t: t, conn: conn, text: textproto.NewConn(conn)}
	r.expect(220)
	return r
}

// send writes s as is (CRLF must be included).
func (r *raw) send(s string) {
	r.t.Helper()
	if _, err := io.WriteString(r.conn, s); err != nil {
		r.t.Fatal(err)
	}
}

func (r *raw) expect(code int) string {
	r.t.Helper()
	got, message, err := r.text.ReadResponse(0)
	if err != nil && got == 0 {
		r.t.Fatalf("reading reply (want %d): %v", code, err)
	}
	if got != code {
		r.t.Fatalf("reply %d %q, want %d", got, message, code)
	}
	return message
}

func (r *raw) cmd(command string, code int) string {
	r.t.Helper()
	r.send(command + "\r\n")
	return r.expect(code)
}

const testMessage = "From: sender@example.org\r\nTo: box@example.test\r\nSubject: test\r\n\r\nHello\r\n"

func TestDeliverWithNetSMTP(t *testing.T) {
	ts := start(t, ModeMX, false, nil)
	err := smtp.SendMail(ts.addr, nil, "sender@example.org", []string{"Box@Example.test", "other@example.test"}, []byte(testMessage))
	if err != nil {
		t.Fatal(err)
	}
	got := ts.backend.deliveries()
	if len(got) != 1 {
		t.Fatalf("%d deliveries, want 1", len(got))
	}
	env, data := got[0].env, string(got[0].data)
	if strings.Join(env.Recipients, ",") != "box@example.test,other@example.test" {
		t.Errorf("recipients = %v", env.Recipients)
	}
	if env.MailFrom != "sender@example.org" || env.Helo != "localhost" || env.TLS || env.Mode != "mx" || env.RemoteAddr != "127.0.0.1" {
		t.Errorf("envelope = %+v", env)
	}
	if !strings.HasPrefix(data, "Received: from localhost ([127.0.0.1])\r\n\tby mx.example.test with ESMTP id "+env.ID+";\r\n") {
		t.Errorf("Received header:\n%s", data)
	}
	if !strings.HasSuffix(data, "\r\n"+testMessage) {
		t.Errorf("message body not preserved:\n%q", data)
	}
}

func TestDotStuffingAndLineEndings(t *testing.T) {
	ts := start(t, ModeMX, false, nil)
	r := dialRaw(t, ts.addr)
	r.cmd("EHLO client", 250)
	r.cmd("MAIL FROM:<>", 250)
	r.cmd("RCPT TO:<box@example.test>", 250)
	r.cmd("DATA", 354)
	r.send("Subject: dots\r\n\r\n..leading dot\r\n...\r\nbare LF\nend\r\n.\r\n")
	r.expect(250)

	data := string(ts.backend.deliveries()[0].data)
	want := "Subject: dots\r\n\r\n.leading dot\r\n..\r\nbare LF\nend\r\n"
	if !strings.HasSuffix(data, want) {
		t.Errorf("body = %q, want suffix %q", data, want)
	}
	if !strings.Contains(data, "\tfor <box@example.test>;") {
		t.Errorf("single recipient missing from Received header:\n%s", data)
	}
}

func TestSizeLimit(t *testing.T) {
	ts := start(t, ModeMX, false, func(s *Server) { s.MaxMessageSize = 100 })
	r := dialRaw(t, ts.addr)
	if ehlo := r.cmd("EHLO client", 250); !strings.Contains(ehlo, "SIZE 100") {
		t.Errorf("EHLO does not announce SIZE 100:\n%s", ehlo)
	}
	r.cmd("MAIL FROM:<a@example.org> SIZE=101", 552)

	r.cmd("MAIL FROM:<a@example.org> SIZE=50 BODY=8BITMIME", 250)
	r.cmd("RCPT TO:<box@example.test>", 250)
	r.cmd("DATA", 354)
	r.send(strings.Repeat("x", 150) + "\r\n.\r\n")
	r.expect(552)

	// The session is still usable and the transaction was reset.
	r.cmd("RCPT TO:<box@example.test>", 503)
	r.cmd("MAIL FROM:<a@example.org>", 250)
	r.cmd("RCPT TO:<box@example.test>", 250)
	r.cmd("DATA", 354)
	r.send("small\r\n.\r\n")
	r.expect(250)
	if n := len(ts.backend.deliveries()); n != 1 {
		t.Errorf("%d deliveries, want 1", n)
	}
}

func TestRecipients(t *testing.T) {
	ts := start(t, ModeMX, false, func(s *Server) { s.MaxRecipients = 2 })
	r := dialRaw(t, ts.addr)
	r.cmd("EHLO client", 250)
	r.cmd("MAIL FROM:<a@example.org>", 250)
	r.cmd("RCPT TO:<unknown@example.test>", 550)
	r.cmd("RCPT TO:<box@relay.example>", 550)
	r.cmd("RCPT TO:<no-domain>", 501)
	r.cmd("RCPT TO:box@example.test", 501)
	r.cmd("RCPT TO:<box@example.test> NOTIFY=NEVER", 555)
	r.cmd("DATA", 554)
	r.cmd("RCPT TO:<@hop.example:BOX@example.test>", 250)
	r.cmd("RCPT TO:<box@example.test>", 250)
	r.cmd("RCPT TO:<other@example.test>", 250)
	r.cmd("RCPT TO:<third@example.test>", 452)
}

func TestCommandSequence(t *testing.T) {
	ts := start(t, ModeMX, false, func(s *Server) { s.MaxErrors = 20 })
	r := dialRaw(t, ts.addr)
	r.cmd("MAIL FROM:<a@example.org>", 503)
	r.cmd("EHLO", 501)
	r.cmd("HELO client", 250)
	r.cmd("RCPT TO:<box@example.test>", 503)
	r.cmd("DATA", 503)
	r.cmd("MAIL FROM:<a@example.org>", 250)
	r.cmd("MAIL FROM:<a@example.org>", 503)
	r.cmd("RSET", 250)
	r.cmd("MAIL FROM:a@example.org", 501)
	r.cmd("MAIL FROM:<a@example.org> AUTH=<>", 555)
	r.cmd("STARTTLS", 502)
	r.cmd("VRFY box", 252)
	r.cmd("NOOP", 250)
	r.cmd("FOO", 500)
	r.send(strings.Repeat("x", 2000) + "\r\n")
	r.expect(500)
	r.cmd("QUIT", 221)
}

func TestTooManyErrors(t *testing.T) {
	ts := start(t, ModeMX, false, func(s *Server) { s.MaxErrors = 3 })
	r := dialRaw(t, ts.addr)
	r.cmd("FOO", 500)
	r.cmd("FOO", 500)
	r.send("FOO\r\n")
	r.expect(500)
	r.expect(421)
	if _, err := r.text.ReadLine(); err == nil {
		t.Error("connection still open after 421")
	}
}

func TestPipelining(t *testing.T) {
	ts := start(t, ModeMX, false, nil)
	r := dialRaw(t, ts.addr)
	r.send("EHLO client\r\nMAIL FROM:<a@example.org>\r\nRCPT TO:<box@example.test>\r\nRCPT TO:<nobody@example.test>\r\nDATA\r\n")
	if ehlo := r.expect(250); !strings.Contains(ehlo, "PIPELINING") {
		t.Errorf("EHLO does not announce PIPELINING:\n%s", ehlo)
	}
	r.expect(250)
	r.expect(250)
	r.expect(550)
	r.expect(354)
	r.send("Subject: pipelined\r\n\r\nbody\r\n.\r\nQUIT\r\n")
	r.expect(250)
	r.expect(221)
	if n := len(ts.backend.deliveries()); n != 1 {
		t.Errorf("%d deliveries, want 1", n)
	}
}

func TestStartTLSOnMX(t *testing.T) {
	ts := start(t, ModeMX, true, nil)
	c, err := smtp.Dial(ts.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if ok, _ := c.Extension("STARTTLS"); !ok {
		t.Fatal("STARTTLS not announced")
	}
	if err := c.StartTLS(ts.clientTLS()); err != nil {
		t.Fatal(err)
	}
	if ok, _ := c.Extension("STARTTLS"); ok {
		t.Error("STARTTLS announced again after TLS")
	}
	sendWith(t, c)
	env := ts.backend.deliveries()[0].env
	if !env.TLS || env.TLSVersion == "" {
		t.Errorf("envelope TLS = %v %q", env.TLS, env.TLSVersion)
	}
	if !bytes.Contains(ts.backend.deliveries()[0].data, []byte("with ESMTPS id")) {
		t.Error("Received header does not say ESMTPS")
	}
}

func TestMXWithoutTLSIsAccepted(t *testing.T) {
	ts := start(t, ModeMX, true, nil)
	r := dialRaw(t, ts.addr)
	r.cmd("EHLO client", 250)
	r.cmd("MAIL FROM:<a@example.org>", 250)
}

func TestSubmissionRequiresStartTLS(t *testing.T) {
	ts := start(t, ModeSubmission, true, nil)
	r := dialRaw(t, ts.addr)
	r.cmd("EHLO client", 250)
	r.cmd("MAIL FROM:<a@example.org>", 530)

	c, err := smtp.Dial(ts.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.StartTLS(ts.clientTLS()); err != nil {
		t.Fatal(err)
	}
	sendWith(t, c)
	if env := ts.backend.deliveries()[0].env; env.Mode != "submission" || !env.TLS {
		t.Errorf("envelope = %+v", env)
	}
}

func TestImplicitTLS(t *testing.T) {
	ts := start(t, ModeImplicitTLS, true, nil)
	conn, err := tls.Dial("tcp", ts.addr, ts.clientTLS())
	if err != nil {
		t.Fatal(err)
	}
	c, err := smtp.NewClient(conn, "mx.example.test")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if ok, _ := c.Extension("STARTTLS"); ok {
		t.Error("STARTTLS announced on an implicit TLS port")
	}
	sendWith(t, c)
	if env := ts.backend.deliveries()[0].env; env.Mode != "smtps" || !env.TLS {
		t.Errorf("envelope = %+v", env)
	}
}

// Commands pipelined after STARTTLS were sent in clear text and must not be
// executed once TLS is established (CVE-2011-0411).
func TestStartTLSDropsInjectedCommands(t *testing.T) {
	ts := start(t, ModeMX, true, nil)
	r := dialRaw(t, ts.addr)
	r.cmd("EHLO client", 250)
	r.send("STARTTLS\r\nMAIL FROM:<injected@example.org>\r\n")
	r.expect(220)

	tlsConn := tls.Client(r.conn, ts.clientTLS())
	if err := tlsConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	secure := &raw{t: t, conn: tlsConn, text: textproto.NewConn(tlsConn)}
	secure.cmd("EHLO client", 250)
	secure.cmd("RCPT TO:<box@example.test>", 503)
}

func TestImplicitTLSRequiresConfig(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{Hostname: "mx", Backend: &fakeBackend{}}
	if err := srv.Serve(l, ModeImplicitTLS); err == nil {
		t.Error("Serve without TLSConfig in implicit TLS mode should fail")
	}
}

func TestTooManyConnections(t *testing.T) {
	ts := start(t, ModeMX, false, func(s *Server) { s.MaxConnections = 1 })
	dialRaw(t, ts.addr)

	conn, err := net.Dial("tcp", ts.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	code, _, err := textproto.NewConn(conn).ReadResponse(0)
	if code != 421 {
		t.Errorf("second connection got %d (%v), want 421", code, err)
	}
}

func sendWith(t *testing.T, c *smtp.Client) {
	t.Helper()
	if err := c.Mail("sender@example.org"); err != nil {
		t.Fatal(err)
	}
	if err := c.Rcpt("box@example.test"); err != nil {
		t.Fatal(err)
	}
	w, err := c.Data()
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(w, testMessage)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.Quit(); err != nil {
		t.Fatal(err)
	}
}
