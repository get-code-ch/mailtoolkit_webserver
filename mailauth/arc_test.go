package mailauth

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

// arc-chain.eml is sealed by dkimpy (see testdata/gen_arc.py): a mailing
// list changed the subject after sealing, which broke DKIM, then a
// forwarding service sealed the chain again.
func TestVerifyARC(t *testing.T) {
	resolver := dkimResolver(t)
	raw := readVector(t, "arc-chain.eml")

	got := VerifyARC(context.Background(), resolver, ParseMessage(raw))
	if got.Result != ResultPass || len(got.Sets) != 2 {
		t.Fatalf("result %s (%s), %d sets", got.Result, got.Reason, len(got.Sets))
	}
	first := got.Sets[0]
	if first.ChainValidation != "none" || first.AuthServer != "lists.example.com" || first.Seal != ResultPass || got.Sets[1].Signature != ResultPass {
		t.Errorf("sets = %+v", got.Sets)
	}
	original := got.OriginalResults()
	if len(original) != 2 || original[0].Method != "dkim" || original[0].Result != ResultPass {
		t.Errorf("original results = %+v", original)
	}
	// DKIM itself fails: the subject was changed after the signature.
	if dkim := VerifyDKIM(context.Background(), resolver, ParseMessage(raw)); dkim[0].Result != ResultFail {
		t.Errorf("DKIM = %s", dkim[0].Result)
	}

	tests := []struct {
		name, old, new, reason string
	}{
		{"body changed after the last seal", "Hi.", "Ho.", "signature du message"},
		{"recorded results forged", "i=1; lists.example.com;", "i=1; evil.example.com;", "sceau"},
		{"set removed", "ARC-Seal: i=1;", "X-Removed: i=1;", "incomplète"},
		{"wrong cv", "cv=pass", "cv=fail", "cv=fail"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			changed := bytes.Replace(raw, []byte(tt.old), []byte(tt.new), 1)
			if bytes.Equal(changed, raw) {
				t.Fatalf("%q not found", tt.old)
			}
			got := VerifyARC(context.Background(), resolver, ParseMessage(changed))
			if got.Result != ResultFail || !strings.Contains(got.Reason, tt.reason) || got.OriginalResults() != nil {
				t.Errorf("result %s (%s), want fail (%s)", got.Result, got.Reason, tt.reason)
			}
		})
	}

	if none := VerifyARC(context.Background(), resolver, ParseMessage(readVector(t, "dkim-relaxed-relaxed.eml"))); none.Result != ResultNone {
		t.Errorf("no chain: %+v", none)
	}
}
