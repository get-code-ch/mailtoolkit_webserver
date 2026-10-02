package smtpd

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// maxCommandLine is the longest accepted command line, CRLF included
// (RFC 5321 §4.5.3.1.4 sets 512, extensions may need more).
const maxCommandLine = 1000

var errLineTooLong = errors.New("line too long")

type session struct {
	srv  *Server
	mode Mode
	conn net.Conn
	br   *bufio.Reader
	bw   *bufio.Writer

	tls        bool
	tlsVersion string
	remoteIP   string
	helo       string
	ehlo       bool
	errors     int

	// Current transaction
	hasFrom bool
	from    string
	rcpts   []string
}

func (s *Server) newSession(conn net.Conn, mode Mode) *session {
	ip := conn.RemoteAddr().String()
	if host, _, err := net.SplitHostPort(ip); err == nil {
		ip = host
	}
	return &session{
		srv:      s,
		mode:     mode,
		conn:     conn,
		br:       bufio.NewReaderSize(conn, 4096),
		bw:       bufio.NewWriter(conn),
		remoteIP: ip,
	}
}

func (ss *session) serve() {
	defer func() { ss.conn.Close() }()

	if tlsConn, ok := ss.conn.(*tls.Conn); ok {
		ss.conn.SetDeadline(time.Now().Add(ss.srv.Timeout))
		if err := tlsConn.Handshake(); err != nil {
			ss.srv.Logger.Printf("smtpd: %s TLS handshake: %v", ss.remoteIP, err)
			return
		}
		ss.setTLS(tlsConn)
	}

	if !ss.reply(220, ss.srv.Hostname+" ESMTP ready") {
		return
	}
	for {
		ss.conn.SetDeadline(time.Now().Add(ss.srv.Timeout))
		line, err := ss.readCommand()
		if errors.Is(err, errLineTooLong) {
			ss.reply(500, "5.5.2 Line too long")
		} else if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				ss.reply(421, "4.4.2 "+ss.srv.Hostname+" Idle timeout, closing connection")
			}
			return
		} else if !ss.handle(line) {
			return
		}
		if ss.errors >= ss.srv.MaxErrors {
			ss.reply(421, "4.7.0 Too many errors, closing connection")
			return
		}
	}
}

// handle runs one command and reports whether the session continues.
func (ss *session) handle(line string) bool {
	verb, arg, _ := strings.Cut(line, " ")
	verb = strings.ToUpper(verb)
	arg = strings.TrimSpace(arg)

	switch verb {
	case "EHLO", "HELO":
		if arg == "" {
			return ss.reply(501, "5.5.4 Syntax: "+verb+" hostname")
		}
		ss.resetTransaction()
		ss.helo, ss.ehlo = arg, verb == "EHLO"
		if !ss.ehlo {
			return ss.reply(250, ss.srv.Hostname)
		}
		lines := []string{
			ss.srv.Hostname + " greets " + arg,
			"PIPELINING",
			"SIZE " + strconv.FormatInt(ss.srv.MaxMessageSize, 10),
			"8BITMIME",
		}
		if ss.srv.TLSConfig != nil && !ss.tls {
			lines = append(lines, "STARTTLS")
		}
		return ss.reply(250, lines...)

	case "STARTTLS":
		return ss.startTLS(arg)
	case "MAIL":
		return ss.mail(arg)
	case "RCPT":
		return ss.rcpt(arg)
	case "DATA":
		return ss.data(arg)
	case "RSET":
		ss.resetTransaction()
		return ss.reply(250, "2.0.0 OK")
	case "NOOP":
		return ss.reply(250, "2.0.0 OK")
	case "VRFY":
		return ss.reply(252, "2.5.2 Cannot VRFY user")
	case "HELP":
		return ss.reply(214, "2.0.0 See RFC 5321")
	case "QUIT":
		ss.reply(221, "2.0.0 Bye")
		return false
	default:
		return ss.reply(500, "5.5.2 Command not recognized")
	}
}

func (ss *session) startTLS(arg string) bool {
	switch {
	case ss.tls:
		return ss.reply(503, "5.5.1 TLS already active")
	case ss.srv.TLSConfig == nil:
		return ss.reply(502, "5.5.1 STARTTLS not supported")
	case arg != "":
		return ss.reply(501, "5.5.4 Syntax: STARTTLS")
	}
	if !ss.reply(220, "2.0.0 Ready to start TLS") {
		return false
	}

	tlsConn := tls.Server(ss.conn, ss.srv.TLSConfig)
	tlsConn.SetDeadline(time.Now().Add(ss.srv.Timeout))
	if err := tlsConn.Handshake(); err != nil {
		ss.srv.Logger.Printf("smtpd: %s STARTTLS handshake: %v", ss.remoteIP, err)
		return false
	}
	// New buffers drop any plaintext pipelined after STARTTLS, which would
	// otherwise be executed as if it was encrypted (CVE-2011-0411).
	ss.conn = tlsConn
	ss.br = bufio.NewReaderSize(tlsConn, 4096)
	ss.bw = bufio.NewWriter(tlsConn)
	ss.setTLS(tlsConn)
	// RFC 3207 §4.2: forget everything learnt before TLS.
	ss.helo, ss.ehlo = "", false
	ss.resetTransaction()
	return true
}

func (ss *session) setTLS(conn *tls.Conn) {
	ss.tls = true
	ss.tlsVersion = tls.VersionName(conn.ConnectionState().Version)
}

func (ss *session) mail(arg string) bool {
	switch {
	case ss.helo == "":
		return ss.reply(503, "5.5.1 Send EHLO first")
	case ss.mode == ModeSubmission && !ss.tls:
		return ss.reply(530, "5.7.0 Must issue a STARTTLS command first")
	case ss.hasFrom:
		return ss.reply(503, "5.5.1 Nested MAIL command")
	}
	path, params, ok := parsePath(arg, "FROM:")
	if !ok {
		return ss.reply(501, "5.5.4 Syntax: MAIL FROM:<address>")
	}
	for _, param := range params {
		key, value, _ := strings.Cut(param, "=")
		switch strings.ToUpper(key) {
		case "SIZE":
			size, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return ss.reply(501, "5.5.4 Invalid SIZE parameter")
			}
			if size > ss.srv.MaxMessageSize {
				return ss.reply(552, "5.3.4 Message size exceeds fixed limit")
			}
		case "BODY":
			if v := strings.ToUpper(value); v != "7BIT" && v != "8BITMIME" {
				return ss.reply(501, "5.5.4 Unsupported BODY type")
			}
		default:
			return ss.reply(555, "5.5.4 Unsupported parameter "+key)
		}
	}
	ss.hasFrom, ss.from = true, path
	return ss.reply(250, "2.1.0 OK")
}

func (ss *session) rcpt(arg string) bool {
	if !ss.hasFrom {
		return ss.reply(503, "5.5.1 Need MAIL command first")
	}
	path, params, ok := parsePath(arg, "TO:")
	if !ok || path == "" {
		return ss.reply(501, "5.5.4 Syntax: RCPT TO:<address>")
	}
	if len(params) > 0 {
		return ss.reply(555, "5.5.4 Unsupported parameter "+params[0])
	}
	if len(ss.rcpts) >= ss.srv.MaxRecipients {
		return ss.reply(452, "4.5.3 Too many recipients")
	}
	address := strings.ToLower(path)
	local, domain, ok := strings.Cut(address, "@")
	if !ok || local == "" || domain == "" || strings.Contains(domain, "@") {
		return ss.reply(501, "5.1.3 Bad recipient address syntax")
	}
	if !ss.srv.Backend.ValidRecipient(address) {
		return ss.reply(550, "5.1.1 Mailbox unavailable")
	}
	for _, r := range ss.rcpts {
		if r == address {
			return ss.reply(250, "2.1.5 OK")
		}
	}
	ss.rcpts = append(ss.rcpts, address)
	return ss.reply(250, "2.1.5 OK")
}

func (ss *session) data(arg string) bool {
	switch {
	case arg != "":
		return ss.reply(501, "5.5.4 Syntax: DATA")
	case !ss.hasFrom:
		return ss.reply(503, "5.5.1 Need MAIL command first")
	case len(ss.rcpts) == 0:
		return ss.reply(554, "5.5.1 No valid recipients")
	}
	if !ss.reply(354, "End data with <CR><LF>.<CR><LF>") {
		return false
	}

	ss.conn.SetDeadline(time.Now().Add(ss.srv.DataTimeout))
	body, tooBig, err := ss.readData()
	if err != nil {
		return false
	}
	defer ss.resetTransaction()
	if tooBig {
		return ss.reply(552, "5.3.4 Message size exceeds fixed limit")
	}

	env := Envelope{
		ID:         NewID(),
		Mode:       ss.mode.String(),
		RemoteAddr: ss.remoteIP,
		Helo:       ss.helo,
		MailFrom:   ss.from,
		Recipients: append([]string(nil), ss.rcpts...),
		TLS:        ss.tls,
		TLSVersion: ss.tlsVersion,
		Received:   time.Now().UTC(),
	}
	message := append(ss.receivedHeader(env), body...)
	if err := ss.srv.Backend.Deliver(env, message); err != nil {
		ss.srv.Logger.Printf("smtpd: %s delivery failed: %v", env.ID, err)
		return ss.reply(451, "4.3.0 Local error, try again later")
	}
	ss.srv.Logger.Printf("smtpd: %s accepted from %s (%s) mail_from=<%s> rcpt=%v size=%d tls=%v",
		env.ID, env.RemoteAddr, env.Mode, env.MailFrom, env.Recipients, len(message), env.TLS)
	return ss.reply(250, "2.0.0 OK queued as "+env.ID)
}

// receivedHeader builds the trace header (RFC 5321 §4.4, RFC 3848 protocol
// names).
func (ss *session) receivedHeader(env Envelope) []byte {
	protocol := "SMTP"
	if ss.ehlo {
		protocol = "ESMTP"
	}
	if ss.tls {
		protocol += "S"
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "Received: from %s ([%s])\r\n\tby %s with %s id %s",
		sanitize(env.Helo), env.RemoteAddr, ss.srv.Hostname, protocol, env.ID)
	if len(env.Recipients) == 1 {
		fmt.Fprintf(&b, "\r\n\tfor <%s>", env.Recipients[0])
	}
	fmt.Fprintf(&b, ";\r\n\t%s\r\n", env.Received.Format(time.RFC1123Z))
	return b.Bytes()
}

// readData reads a dot-terminated message, removing the dot-stuffing but
// keeping line endings untouched. Once the message exceeds the size limit,
// the rest is read and discarded.
func (ss *session) readData() (data []byte, tooBig bool, err error) {
	var buffer bytes.Buffer
	atLineStart := true
	for {
		chunk, err := ss.br.ReadSlice('\n')
		if err != nil && err != bufio.ErrBufferFull {
			return nil, false, err
		}
		if atLineStart {
			if string(chunk) == ".\r\n" || string(chunk) == ".\n" {
				return buffer.Bytes(), tooBig, nil
			}
			if len(chunk) > 0 && chunk[0] == '.' {
				chunk = chunk[1:]
			}
		}
		atLineStart = err == nil
		if tooBig {
			continue
		}
		if int64(buffer.Len()+len(chunk)) > ss.srv.MaxMessageSize {
			tooBig = true
			buffer = bytes.Buffer{}
			continue
		}
		buffer.Write(chunk)
	}
}

// readCommand reads a command line without its line ending.
func (ss *session) readCommand() (string, error) {
	line, err := ss.br.ReadSlice('\n')
	if err == bufio.ErrBufferFull || (err == nil && len(line) > maxCommandLine) {
		for err == bufio.ErrBufferFull {
			_, err = ss.br.ReadSlice('\n')
		}
		if err != nil {
			return "", err
		}
		return "", errLineTooLong
	}
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(line), "\r\n"), nil
}

// reply writes a (multi-line) reply and reports whether it was sent.
func (ss *session) reply(code int, lines ...string) bool {
	if code >= 500 {
		ss.errors++
	}
	for i, line := range lines {
		separator := " "
		if i < len(lines)-1 {
			separator = "-"
		}
		fmt.Fprintf(ss.bw, "%d%s%s\r\n", code, separator, line)
	}
	return ss.bw.Flush() == nil
}

func (ss *session) resetTransaction() {
	ss.hasFrom, ss.from, ss.rcpts = false, "", nil
}

// parsePath parses "FROM:<path> PARAM=value..." (prefix "FROM:" or "TO:").
// A source route (<@a,@b:user@c>) is removed. The null path <> is valid.
func parsePath(arg, prefix string) (path string, params []string, ok bool) {
	if len(arg) < len(prefix) || !strings.EqualFold(arg[:len(prefix)], prefix) {
		return "", nil, false
	}
	rest := strings.TrimSpace(arg[len(prefix):])
	if !strings.HasPrefix(rest, "<") {
		return "", nil, false
	}
	end := strings.IndexByte(rest, '>')
	if end < 0 {
		return "", nil, false
	}
	path = rest[1:end]
	if strings.HasPrefix(path, "@") {
		if i := strings.IndexByte(path, ':'); i >= 0 {
			path = path[i+1:]
		}
	}
	return path, strings.Fields(rest[end+1:]), true
}

// sanitize keeps the printable ASCII characters of a client supplied value
// before writing it in a header.
func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x21 || r > 0x7e {
			return -1
		}
		return r
	}, s)
}
