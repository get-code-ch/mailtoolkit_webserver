package mailauth

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// maxARCSets is the highest instance accepted (RFC 8617 §4.2.1).
const maxARCSets = 50

// ARCResult is the validation of the ARC chain of a message (RFC 8617).
// Each intermediary that forwarded the mail (mailing list, forwarding
// service, security gateway) records the authentication results it saw in
// an ARC set and seals the chain: a valid chain proves those results even
// when the forwarding broke DKIM.
type ARCResult struct {
	// Result is none (no chain), pass or fail.
	Result string
	Reason string
	Sets   []ARCSet
}

// ARCSet is one instance of the chain, oldest (i=1) first.
type ARCSet struct {
	Instance int
	// Sealer is the d= domain of the ARC-Seal, the intermediary.
	Sealer   string
	Selector string
	// ChainValidation is the cv= tag: the chain status seen by the sealer.
	ChainValidation string
	// AuthServer and Results are the ARC-Authentication-Results recorded
	// by the sealer.
	AuthServer string
	Results    []ProviderResult
	// Seal and Signature are the verification of the ARC-Seal and of the
	// ARC-Message-Signature, empty when not checked.
	Seal      string
	Signature string
	// SignatureReason explains a failed ARC-Message-Signature.
	SignatureReason string
}

// OriginalResults returns the results recorded by the first intermediary,
// closest to the sender, when the chain is valid.
func (r ARCResult) OriginalResults() []ProviderResult {
	if r.Result != ResultPass || len(r.Sets) == 0 {
		return nil
	}
	return r.Sets[0].Results
}

type arcFields struct{ aar, ams, as int }

// VerifyARC validates the ARC chain of a message.
func VerifyARC(ctx context.Context, resolver Resolver, m Message) ARCResult {
	sets := map[int]*arcFields{}
	highest := 0
	result := ARCResult{Result: ResultNone}
	fail := func(format string, args ...any) ARCResult {
		result.Result, result.Reason = ResultFail, fmt.Sprintf(format, args...)
		return result
	}
	for i, f := range m.Fields {
		var kind int
		switch strings.ToLower(f.Name) {
		case "arc-authentication-results":
			kind = 0
		case "arc-message-signature":
			kind = 1
		case "arc-seal":
			kind = 2
		default:
			continue
		}
		instance := arcInstance(f.Value)
		if instance < 1 || instance > maxARCSets {
			return fail("instance ARC invalide dans %s", f.Name)
		}
		set := sets[instance]
		if set == nil {
			set = &arcFields{-1, -1, -1}
			sets[instance] = set
		}
		slot := []*int{&set.aar, &set.ams, &set.as}[kind]
		if *slot >= 0 {
			return fail("deux champs %s pour l'instance %d", f.Name, instance)
		}
		*slot = i
		highest = max(highest, instance)
	}
	if len(sets) == 0 {
		result.Reason = "aucune chaîne ARC : le mail n'est pas passé par un intermédiaire qui l'a scellé"
		return result
	}

	for i := 1; i <= highest; i++ {
		set := sets[i]
		if set == nil || set.aar < 0 || set.ams < 0 || set.as < 0 {
			return fail("chaîne incomplète : l'instance %d manque ou est partielle", i)
		}
		seal := tagMap(m.Fields[set.as].Value)
		s := ARCSet{Instance: i, Sealer: strings.ToLower(seal["d"]), Selector: seal["s"], ChainValidation: strings.ToLower(seal["cv"])}
		aar := m.Fields[set.aar].Value
		if _, rest, ok := strings.Cut(aar, ";"); ok {
			s.Results = ParseAuthResults("ARC-Authentication-Results", rest)
			if len(s.Results) > 0 {
				s.AuthServer = s.Results[0].Server
			}
		}
		result.Sets = append(result.Sets, s)
	}

	// The newest sealer saw the chain as failed: nothing more to check.
	last := &result.Sets[highest-1]
	if last.ChainValidation == ResultFail {
		return fail("le dernier intermédiaire (%s) a lui-même trouvé la chaîne invalide (cv=fail)", last.Sealer)
	}
	for i := range result.Sets {
		want := ResultPass
		if i == 0 {
			want = ResultNone
		}
		if result.Sets[i].ChainValidation != want {
			return fail("instance %d : cv=%s au lieu de cv=%s", i+1, result.Sets[i].ChainValidation, want)
		}
	}

	// The newest ARC-Message-Signature covers the message as received.
	ams := verifyMessageSignature(ctx, resolver, m, sets[highest].ams, true)
	last.Signature, last.SignatureReason = ams.Result, ams.Reason
	if ams.Result != ResultPass {
		return fail("signature du message de %s (instance %d) : %s", last.Sealer, highest, ams.Reason)
	}

	// Each seal covers the sets up to its own instance.
	for i := highest; i >= 1; i-- {
		status, reason := verifySeal(ctx, resolver, m, sets, i)
		result.Sets[i-1].Seal = status
		if status != ResultPass {
			return fail("sceau de %s (instance %d) : %s", result.Sets[i-1].Sealer, i, reason)
		}
	}
	result.Result = ResultPass
	result.Reason = fmt.Sprintf("chaîne de %d intermédiaire%s valide", highest, map[bool]string{true: "s", false: ""}[highest > 1])
	return result
}

// verifySeal verifies the ARC-Seal of an instance (RFC 8617 §5.1.1): the
// relaxed ARC sets 1 to instance, in order, the seal itself with an empty
// b= and without its final CRLF.
func verifySeal(ctx context.Context, resolver Resolver, m Message, sets map[int]*arcFields, instance int) (string, string) {
	seal := m.Fields[sets[instance].as]
	tags, err := parseTags(seal.Value)
	if err != nil {
		return ResultPermError, fmt.Sprintf("sceau illisible : %v", err)
	}
	for _, name := range []string{"a", "b", "cv", "d", "i", "s"} {
		if _, ok := tags[name]; !ok {
			return ResultPermError, fmt.Sprintf("paramètre %s= manquant", name)
		}
	}
	if _, ok := tags["h"]; ok {
		return ResultPermError, "paramètre h= interdit dans un sceau"
	}
	keyType := "rsa"
	switch strings.ToLower(tags["a"]) {
	case "rsa-sha256":
	case "ed25519-sha256":
		keyType = "ed25519"
	default:
		return ResultPermError, fmt.Sprintf("algorithme %q non supporté", tags["a"])
	}

	h := sha256.New()
	for i := 1; i <= instance; i++ {
		set := sets[i]
		for _, index := range []int{set.aar, set.ams, set.as} {
			raw := m.Fields[index].Raw
			if i == instance && index == set.as {
				h.Write([]byte(strings.TrimSuffix(canonicalHeader(removeSignatureValue(raw), "relaxed"), "\r\n")))
				continue
			}
			h.Write([]byte(canonicalHeader(raw, "relaxed")))
		}
	}
	digest := h.Sum(nil)

	signature, err := base64.StdEncoding.DecodeString(tags["b"])
	if err != nil {
		return ResultPermError, "signature b= illisible"
	}
	key, err := lookupKey(ctx, resolver, tags["s"], strings.ToLower(tags["d"]))
	if err != nil {
		if e, ok := err.(*spfError); ok {
			return e.result, e.reason
		}
		return ResultTempError, err.Error()
	}
	if key.keyType != keyType {
		return ResultPermError, fmt.Sprintf("clé de type %s pour un sceau %s", key.keyType, tags["a"])
	}
	switch k := key.key.(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() < 1024 {
			return ResultPermError, fmt.Sprintf("clé RSA de %d bits, trop courte", k.N.BitLen())
		}
		if rsa.VerifyPKCS1v15(k, crypto.SHA256, digest, signature) != nil {
			return ResultFail, "sceau invalide : la chaîne a été modifiée, ou la clé a changé"
		}
	case ed25519.PublicKey:
		if !ed25519.Verify(k, digest, signature) {
			return ResultFail, "sceau invalide : la chaîne a été modifiée, ou la clé a changé"
		}
	}
	return ResultPass, ""
}

// arcInstance reads the i= tag of an ARC field, 0 when missing.
func arcInstance(value string) int {
	for _, t := range ParseTags(value) {
		if t.Name == "i" {
			n, err := strconv.Atoi(t.Value)
			if err != nil {
				return 0
			}
			return n
		}
	}
	return 0
}

// tagMap returns the tags of a tag-list, lower-case names, first value
// kept.
func tagMap(value string) map[string]string {
	tags := map[string]string{}
	for _, t := range ParseTags(value) {
		if _, dup := tags[t.Name]; !dup {
			tags[t.Name] = t.Value
		}
	}
	return tags
}
