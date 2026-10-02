package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/get-code-ch/mailtoolkit_webserver/smtpd"
)

type testClock struct{ now time.Time }

func (c *testClock) Now() time.Time { return c.now }

func newTestStore(t *testing.T, folder string, clock *testClock) *mailboxStore {
	t.Helper()
	store, err := newMailboxStoreClock(folder, []string{"Analyzer.test", "other.test"}, time.Hour, 0, clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.root.Close() })
	return store
}

func deliver(t *testing.T, store *mailboxStore, address string, carrier []byte) smtpd.Envelope {
	t.Helper()
	env := smtpd.Envelope{ID: randomHex(t), Recipients: []string{address}, MailFrom: "user@example.org", Received: time.Now()}
	if err := store.Deliver(env, carrier); err != nil {
		t.Fatal(err)
	}
	return env
}

func randomHex(t *testing.T) string {
	t.Helper()
	b := make([]byte, 12)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func TestCreateMailbox(t *testing.T) {
	clock := &testClock{time.Now()}
	store := newTestStore(t, t.TempDir(), clock)

	seen := map[string]bool{}
	for range 50 {
		mailbox, err := store.Create()
		if err != nil {
			t.Fatal(err)
		}
		if !regexp.MustCompile(`^[a-z2-7]{10}@analyzer\.test$`).MatchString(mailbox.Address) {
			t.Fatalf("address %q", mailbox.Address)
		}
		if !validToken(mailbox.Token) {
			t.Fatalf("token %q", mailbox.Token)
		}
		if seen[mailbox.Address] || seen[mailbox.Token] {
			t.Fatal("duplicate address or token")
		}
		seen[mailbox.Address], seen[mailbox.Token] = true, true
		if !mailbox.Expires.Equal(mailbox.Created.Add(time.Hour)) {
			t.Errorf("expires %v, created %v", mailbox.Expires, mailbox.Created)
		}
	}
}

func TestValidRecipient(t *testing.T) {
	clock := &testClock{time.Now()}
	store := newTestStore(t, t.TempDir(), clock)
	mailbox, err := store.Create()
	if err != nil {
		t.Fatal(err)
	}
	local := mailbox.Address[:10]

	if !store.ValidRecipient(mailbox.Address) {
		t.Error("new mailbox refused")
	}
	for _, address := range []string{"unknown@analyzer.test", local + "@other.test", local + "@relay.example"} {
		if store.ValidRecipient(address) {
			t.Errorf("%s accepted", address)
		}
	}

	clock.now = clock.now.Add(time.Hour)
	if store.ValidRecipient(mailbox.Address) {
		t.Error("expired mailbox accepted")
	}
	if _, ok := store.ByToken(mailbox.Token); ok {
		t.Error("expired mailbox readable")
	}
}

func TestMaxMailboxes(t *testing.T) {
	clock := &testClock{time.Now()}
	store := newTestStore(t, t.TempDir(), clock)
	store.maxMailboxes = 2
	for range 2 {
		if _, err := store.Create(); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.Create(); !errors.Is(err, errTooManyMailboxes) {
		t.Errorf("third mailbox: %v, want errTooManyMailboxes", err)
	}
	clock.now = clock.now.Add(time.Hour)
	if _, err := store.Create(); err != nil {
		t.Errorf("expired mailboxes still counted: %v", err)
	}
}

func TestDeliverAndRead(t *testing.T) {
	clock := &testClock{time.Now()}
	store := newTestStore(t, t.TempDir(), clock)
	mailbox, err := store.Create()
	if err != nil {
		t.Fatal(err)
	}

	suspect := readTestdata(t, "multipartcomplex.eml")
	withMail := deliver(t, store, mailbox.Address, buildCarrier(
		"Content-Type: message/rfc822\r\nContent-Disposition: attachment; filename=\"suspect.eml\"\r\n\r\n"+string(suspect)))
	withoutMail := deliver(t, store, mailbox.Address, buildCarrier())

	submissions, err := store.Submissions(mailbox.Token)
	if err != nil {
		t.Fatal(err)
	}
	if len(submissions) != 2 {
		t.Fatalf("%d submissions, want 2", len(submissions))
	}

	first, err := store.Submission(mailbox.Token, withMail.ID)
	if err != nil {
		t.Fatal(err)
	}
	if first.Envelope.MailFrom != "user@example.org" || len(first.Analyzed) != 1 || first.Error != "" {
		t.Fatalf("submission = %+v", first)
	}
	info := first.Analyzed[0]
	if info.Subject != "Hello Bonjour Coucou !!" || info.From != "info@theatreboulimie.com" || info.Filename != "suspect.eml" {
		t.Errorf("analyzed info = %+v", info)
	}

	mail, _, err := store.Analyzed(mailbox.Token, withMail.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if mail.Header.Subject != "Hello Bonjour Coucou !!" || len(mail.Attachments) != 1 {
		t.Errorf("analyzed mail: subject %q, %d attachments", mail.Header.Subject, len(mail.Attachments))
	}
	stored, err := os.ReadFile(filepath.Join(store.root.Name(), mailbox.Token, withMail.ID, "analyzed-1.eml"))
	if err != nil || string(stored) != string(suspect) {
		t.Errorf("stored mail differs from the original (%v)", err)
	}

	second, err := store.Submission(mailbox.Token, withoutMail.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Analyzed) != 0 || second.Error != errNoAttachedMail {
		t.Errorf("carrier without mail = %+v", second)
	}
}

func TestInvalidReferences(t *testing.T) {
	clock := &testClock{time.Now()}
	store := newTestStore(t, t.TempDir(), clock)
	mailbox, err := store.Create()
	if err != nil {
		t.Fatal(err)
	}
	env := deliver(t, store, mailbox.Address, buildCarrier())

	if _, err := store.Submissions("../" + mailbox.Token); !errors.Is(err, errNotFound) {
		t.Errorf("Submissions with a path: %v", err)
	}
	for _, id := range []string{"..", "../mailbox.json", "000000000000000000000000"} {
		if _, _, err := store.Analyzed(mailbox.Token, id, 1); !errors.Is(err, errNotFound) {
			t.Errorf("Analyzed(%q): %v, want errNotFound", id, err)
		}
	}
	if _, _, err := store.Analyzed(mailbox.Token, env.ID, 1); !errors.Is(err, errNotFound) {
		t.Errorf("Analyzed of a carrier without mail: %v, want errNotFound", err)
	}
}

func TestPurgeAndReload(t *testing.T) {
	folder := t.TempDir()
	clock := &testClock{time.Now()}
	store := newTestStore(t, folder, clock)

	old, err := store.Create()
	if err != nil {
		t.Fatal(err)
	}
	clock.now = clock.now.Add(30 * time.Minute)
	recent, err := store.Create()
	if err != nil {
		t.Fatal(err)
	}
	deliver(t, store, recent.Address, buildCarrier())

	// A restarted server finds the active mailboxes and their mails.
	reloaded := newTestStore(t, folder, clock)
	if !reloaded.ValidRecipient(old.Address) || !reloaded.ValidRecipient(recent.Address) {
		t.Fatal("mailboxes not reloaded")
	}
	if submissions, err := reloaded.Submissions(recent.Token); err != nil || len(submissions) != 1 {
		t.Errorf("reloaded submissions = %v, %v", submissions, err)
	}

	clock.now = clock.now.Add(45 * time.Minute)
	reloaded.PurgeExpired()
	if _, err := os.Stat(filepath.Join(folder, old.Token)); !os.IsNotExist(err) {
		t.Errorf("expired mailbox folder still present: %v", err)
	}
	if _, ok := reloaded.ByToken(recent.Token); !ok {
		t.Error("active mailbox purged")
	}

	// Expired mailboxes are also removed when loading.
	clock.now = clock.now.Add(time.Hour)
	newTestStore(t, folder, clock)
	if _, err := os.Stat(filepath.Join(folder, recent.Token)); !os.IsNotExist(err) {
		t.Errorf("expired mailbox kept at load: %v", err)
	}
}
