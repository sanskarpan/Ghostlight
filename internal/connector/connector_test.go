package connector

import (
	"errors"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 7, 9, 8, 0, 0, 0, time.UTC)

func registry(t *testing.T) Registry {
	t.Helper()
	var r Registry
	var err error
	r, err = r.AddConnector(Connector{
		ID: "slack-acme", Kind: KindSlack, Tenant: "acme", Scope: "workspace:acme",
		Secret: "not-a-real-signing-key",
	})
	if err != nil {
		t.Fatalf("AddConnector: %v", err)
	}
	r, err = r.BindIdentity(Identity{
		ConnectorID: "slack-acme", Scope: "workspace:acme",
		ExternalID: "U0GHOST", Display: "Ghostlight",
	})
	if err != nil {
		t.Fatalf("BindIdentity: %v", err)
	}
	return r
}

// policy allows a couple of fields and redacts secrets wherever they appear.
func policy() Policy {
	return Policy{
		AllowFields:    []string{"service", "environment"},
		DenyFields:     []string{"environment"},
		SecretPatterns: []string{`(?i)token=[A-Za-z0-9]+`, `AKIA[0-9A-Z]{16}`},
	}
}

// ---------------------------------------------------------------------------
// Connectors and identity
// ---------------------------------------------------------------------------

func TestAddConnectorRefusesUnusableConnectors(t *testing.T) {
	cases := map[string]struct {
		mutate func(*Connector)
		want   error
	}{
		"no identifier": {func(c *Connector) { c.ID = "" }, ErrNoConnectorID},
		"no kind":       {func(c *Connector) { c.Kind = "" }, ErrNoKind},
		"unknown kind":  {func(c *Connector) { c.Kind = Kind("carrier-pigeon") }, ErrUnknownKind},
		"no tenant":     {func(c *Connector) { c.Tenant = "" }, ErrNoTenant},
		"no scope":      {func(c *Connector) { c.Scope = "  " }, ErrNoScope},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c := Connector{ID: "c1", Kind: KindSlack, Tenant: "acme", Scope: "workspace:acme"}
			tc.mutate(&c)
			if _, err := (Registry{}).AddConnector(c); !errors.Is(err, tc.want) {
				t.Errorf("AddConnector error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestAddConnectorRefusesDuplicateIdentifiers(t *testing.T) {
	r := registry(t)
	if _, err := r.AddConnector(Connector{ID: "slack-acme", Kind: KindTeams, Tenant: "acme", Scope: "workspace:acme"}); !errors.Is(err, ErrDuplicateConnector) {
		t.Errorf("AddConnector error = %v, want ErrDuplicateConnector", err)
	}
}

// One external account serving two scopes is how a message about one workspace
// arrives with the identity of another.
func TestExternalIdentityCannotServeTwoScopes(t *testing.T) {
	r := registry(t)
	_, err := r.BindIdentity(Identity{
		ConnectorID: "slack-acme", Scope: "workspace:other", ExternalID: "U0GHOST",
	})
	if !errors.Is(err, ErrIdentityInUse) {
		t.Errorf("BindIdentity error = %v, want ErrIdentityInUse", err)
	}
}

// One scope, one identity: the mapping stays one to one and auditable.
func TestScopeCannotHaveTwoIdentities(t *testing.T) {
	r := registry(t)
	_, err := r.BindIdentity(Identity{
		ConnectorID: "slack-acme", Scope: "workspace:acme", ExternalID: "U0OTHER",
	})
	if !errors.Is(err, ErrScopeAlreadyBound) {
		t.Errorf("BindIdentity error = %v, want ErrScopeAlreadyBound", err)
	}
}

// Rebinding the same identity to the same place is idempotent, not an error, so a
// repeated install does not fail.
func TestRebindingTheSameIdentityIsIdempotent(t *testing.T) {
	r := registry(t)
	out, err := r.BindIdentity(Identity{
		ConnectorID: "slack-acme", Scope: "workspace:acme", ExternalID: "U0GHOST",
	})
	if err != nil {
		t.Errorf("BindIdentity: %v", err)
	}
	if len(out.Identities) != len(r.Identities) {
		t.Errorf("identities = %d, want %d", len(out.Identities), len(r.Identities))
	}
}

func TestBindIdentityRefusesIncompleteBindings(t *testing.T) {
	cases := map[string]struct {
		mutate func(*Identity)
		want   error
	}{
		"no connector": {func(i *Identity) { i.ConnectorID = "" }, ErrNoConnectorID},
		"no scope":     {func(i *Identity) { i.Scope = "" }, ErrNoScope},
		"no identity":  {func(i *Identity) { i.ExternalID = "" }, ErrNoExternalID},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			id := Identity{ConnectorID: "slack-acme", Scope: "workspace:acme", ExternalID: "U0GHOST"}
			tc.mutate(&id)
			if _, err := (Registry{}).BindIdentity(id); !errors.Is(err, tc.want) {
				t.Errorf("BindIdentity error = %v, want %v", err, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------------

// Redacting "the fields we know are sensitive" sends everything else, and the field
// nobody thought of is exactly how a credential reaches a channel.
func TestUnnamedFieldsAreRedacted(t *testing.T) {
	p := Policy{AllowFields: []string{"service"}}
	out, err := p.Redact(Payload{Fields: []Field{
		{Name: "service", Value: "api"},
		{Name: "something_new", Value: "surprise"},
	}})
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	if out.Fields[0].Value != "api" {
		t.Errorf("allowlisted field = %q, want api", out.Fields[0].Value)
	}
	if out.Fields[1].Value != Redacted {
		t.Errorf("unnamed field = %q, want it redacted", out.Fields[1].Value)
	}
}

// A deny beats an allow, so a field can be allowed in general and excluded in one
// policy.
func TestDenyBeatsAllow(t *testing.T) {
	p := Policy{AllowFields: []string{"service", "environment"}, DenyFields: []string{"environment"}}
	out, err := p.Redact(Payload{Fields: []Field{
		{Name: "service", Value: "api"},
		{Name: "environment", Value: "prod"},
	}})
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	if out.Fields[1].Value != Redacted {
		t.Errorf("denied field = %q, want it redacted", out.Fields[1].Value)
	}
}

// A name allowlist says which fields may be sent, not that their contents are safe.
func TestSecretPatternRedactsAnAllowlistedField(t *testing.T) {
	p := policy()
	out, err := p.Redact(Payload{Fields: []Field{
		{Name: "service", Value: "api token=abc123"},
	}})
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	if !strings.Contains(out.Fields[0].Value, Redacted) {
		t.Errorf("value = %q, want the secret pattern redacted", out.Fields[0].Value)
	}
	if strings.Contains(out.Fields[0].Value, "abc123") {
		t.Error("the secret must not survive redaction")
	}
}

func TestRedactRefusesUnusablePayloads(t *testing.T) {
	p := Policy{AllowFields: []string{"a", "b"}}
	if _, err := p.Redact(Payload{Fields: []Field{{Name: "  ", Value: "x"}}}); !errors.Is(err, ErrNoFieldName) {
		t.Errorf("Redact error = %v, want ErrNoFieldName", err)
	}
	if _, err := p.Redact(Payload{Fields: []Field{{Name: "a", Value: "1"}, {Name: "a", Value: "2"}}}); !errors.Is(err, ErrDuplicateField) {
		t.Errorf("Redact error = %v, want ErrDuplicateField", err)
	}
}

func TestRedactRefusesABrokenPattern(t *testing.T) {
	p := Policy{SecretPatterns: []string{"([unclosed"}}
	if _, err := p.Redact(Payload{Fields: []Field{{Name: "a", Value: "1"}}}); !errors.Is(err, ErrBadPattern) {
		t.Errorf("Redact error = %v, want ErrBadPattern", err)
	}
	if err := p.Validate(); !errors.Is(err, ErrBadPattern) {
		t.Errorf("Validate error = %v, want ErrBadPattern", err)
	}
}

// Free text is the most likely place to leak, so it is opt-in.
func TestFreeTextIsRedactedByDefault(t *testing.T) {
	r := registry(t)
	d, err := r.Deliver(Notice{
		ConnectorID: "slack-acme", Scope: "workspace:acme",
		Title: "Public bucket found", Body: "the bucket is called prod-artifacts",
	}, Policy{AllowFields: []string{"service"}})
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if d.Title != Redacted || d.Body != Redacted {
		t.Errorf("free text = %q / %q, want both redacted", d.Title, d.Body)
	}
	if !d.Redacted {
		t.Error("the delivery must report that it was redacted")
	}
}

func TestFreeTextIsSentWhenThePolicyOptsIn(t *testing.T) {
	r := registry(t)
	d, err := r.Deliver(Notice{
		ConnectorID: "slack-acme", Scope: "workspace:acme",
		Title: "Public bucket found", Body: "the bucket is called prod-artifacts",
	}, Policy{AllowFields: []string{"service"}, AllowFreeText: true})
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if d.Title != "Public bucket found" {
		t.Errorf("title = %q, want it sent", d.Title)
	}
}

// Free text that is allowed is still subject to the secret patterns.
func TestAllowedFreeTextIsStillPatternChecked(t *testing.T) {
	r := registry(t)
	d, err := r.Deliver(Notice{
		ConnectorID: "slack-acme", Scope: "workspace:acme",
		Title: "finding", Body: "key AKIAEXAMPLEKEYNOTREAL leaked",
	}, Policy{AllowFields: []string{"service"}, AllowFreeText: true, SecretPatterns: []string{`AKIA[0-9A-Z]{16}`}})
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if strings.Contains(d.Body, "AKIAEXAMPLEKEYNOTREAL") {
		t.Errorf("body = %q, want the access key redacted", d.Body)
	}
}

// ---------------------------------------------------------------------------
// Delivery
// ---------------------------------------------------------------------------

func TestDeliverRequiresAKnownConnectorAndBoundIdentity(t *testing.T) {
	r := registry(t)
	if _, err := r.Deliver(Notice{ConnectorID: "nope", Scope: "workspace:acme"}, Policy{}); !errors.Is(err, ErrUnknownConnector) {
		t.Errorf("Deliver error = %v, want ErrUnknownConnector", err)
	}
	// A connector with no identity bound cannot post.
	r2, err := r.AddConnector(Connector{ID: "jira-acme", Kind: KindJira, Tenant: "acme", Scope: "org:acme"})
	if err != nil {
		t.Fatalf("AddConnector: %v", err)
	}
	if _, err := r2.Deliver(Notice{ConnectorID: "jira-acme", Scope: "org:acme"}, Policy{}); !errors.Is(err, ErrNoIdentity) {
		t.Errorf("Deliver error = %v, want ErrNoIdentity", err)
	}
}

// A notice is written for one audience, and the connector's audience is fixed.
func TestDeliverRefusesANoticeForAnotherScope(t *testing.T) {
	r := registry(t)
	if _, err := r.Deliver(Notice{ConnectorID: "slack-acme", Scope: "workspace:other"}, Policy{}); !errors.Is(err, ErrNoScope) {
		t.Errorf("Deliver error = %v, want ErrNoScope", err)
	}
}

// The connector's own secret must never leave, even if it got into a field.
func TestDeliverRefusesASecretInThePayload(t *testing.T) {
	r := registry(t)
	p := Policy{AllowFields: []string{"service", "note"}}
	_, err := r.Deliver(Notice{
		ConnectorID: "slack-acme", Scope: "workspace:acme",
		Fields: []Field{{Name: "note", Value: "the key is not-a-real-signing-key"}},
	}, p)
	if !errors.Is(err, ErrSecretLeak) {
		t.Errorf("Deliver error = %v, want ErrSecretLeak", err)
	}
}

// The delivery posts as the identity bound to that scope.
func TestDeliverUsesTheScopedIdentity(t *testing.T) {
	r := registry(t)
	d, err := r.Deliver(Notice{ConnectorID: "slack-acme", Scope: "workspace:acme"}, Policy{})
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if d.Identity != "U0GHOST" || d.Display != "Ghostlight" {
		t.Errorf("delivery identity = %q / %q, want the bound identity", d.Identity, d.Display)
	}
	if d.Digest == "" {
		t.Error("a delivery must carry a digest")
	}
}

// The same content always digests the same way.
func TestDeliveryDigestIsStable(t *testing.T) {
	r := registry(t)
	notice := Notice{
		ConnectorID: "slack-acme", Scope: "workspace:acme",
		Title: "t", Body: "b",
		Fields: []Field{{Name: "service", Value: "api"}, {Name: "environment", Value: "prod"}},
	}
	p := Policy{AllowFields: []string{"service", "environment"}, AllowFreeText: true}
	first, err := r.Deliver(notice, p)
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	second, err := r.Deliver(notice, p)
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if first.Digest != second.Digest {
		t.Error("two identical deliveries must share a digest")
	}
	changed := notice
	changed.Fields = []Field{{Name: "service", Value: "web"}, {Name: "environment", Value: "prod"}}
	third, err := r.Deliver(changed, p)
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if third.Digest == first.Digest {
		t.Error("a changed delivery must change the digest")
	}
}

// ---------------------------------------------------------------------------
// Signed callbacks
// ---------------------------------------------------------------------------

func TestSignedCallbackVerifies(t *testing.T) {
	r := registry(t)
	cb := Callback{ConnectorID: "slack-acme", Timestamp: now, Nonce: "n-1", Body: []byte(`{"action":"click"}`)}
	signed, err := SignCallback("not-a-real-signing-key", cb)
	if err != nil {
		t.Fatalf("SignCallback: %v", err)
	}
	v := &Verifier{}
	if err := v.Verify(r, signed, now); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

func TestVerifyRefusesUnsignedAndMisSignedCallbacks(t *testing.T) {
	r := registry(t)
	v := &Verifier{}
	cb := Callback{ConnectorID: "slack-acme", Timestamp: now, Nonce: "n-1", Body: []byte("{}")}
	if err := v.Verify(r, cb, now); !errors.Is(err, ErrUnsigned) {
		t.Errorf("Verify error = %v, want ErrUnsigned", err)
	}
	signed, err := SignCallback("not-a-real-signing-key", cb)
	if err != nil {
		t.Fatalf("SignCallback: %v", err)
	}
	forged := signed
	forged.Signature = strings.Repeat("a", 64)
	if err := v.Verify(r, forged, now); !errors.Is(err, ErrBadSignature) {
		t.Errorf("Verify error = %v, want ErrBadSignature", err)
	}
	// A body changed after signing breaks the signature.
	tampered := signed
	tampered.Body = []byte(`{"action":"delete"}`)
	if err := v.Verify(r, tampered, now); !errors.Is(err, ErrBadSignature) {
		t.Errorf("Verify error = %v, want ErrBadSignature", err)
	}
}

// A signature from the future is as suspicious as one from the past.
func TestVerifyRefusesCallbacksOutsideTheWindowInBothDirections(t *testing.T) {
	r := registry(t)
	v := &Verifier{Window: 5 * time.Minute}
	old, err := SignCallback("not-a-real-signing-key", Callback{ConnectorID: "slack-acme", Timestamp: now.Add(-time.Hour), Nonce: "n-old"})
	if err != nil {
		t.Fatalf("SignCallback: %v", err)
	}
	if err := v.Verify(r, old, now); !errors.Is(err, ErrStaleCallback) {
		t.Errorf("Verify error = %v, want ErrStaleCallback", err)
	}
	future, err := SignCallback("not-a-real-signing-key", Callback{ConnectorID: "slack-acme", Timestamp: now.Add(time.Hour), Nonce: "n-future"})
	if err != nil {
		t.Fatalf("SignCallback: %v", err)
	}
	if err := v.Verify(r, future, now); !errors.Is(err, ErrStaleCallback) {
		t.Errorf("Verify error = %v, want ErrStaleCallback", err)
	}
}

// A signature that verifies forever is a permanent credential.
func TestVerifyRefusesAReplayedNonce(t *testing.T) {
	r := registry(t)
	v := &Verifier{}
	cb := Callback{ConnectorID: "slack-acme", Timestamp: now, Nonce: "n-1", Body: []byte("{}")}
	signed, err := SignCallback("not-a-real-signing-key", cb)
	if err != nil {
		t.Fatalf("SignCallback: %v", err)
	}
	if err := v.Verify(r, signed, now); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if err := v.Verify(r, signed, now.Add(time.Second)); !errors.Is(err, ErrReplay) {
		t.Errorf("second Verify error = %v, want ErrReplay", err)
	}
}

func TestVerifyRefusesCallbacksForUnknownConnectorsAndMissingSecrets(t *testing.T) {
	r := registry(t)
	v := &Verifier{}
	cb := Callback{ConnectorID: "nope", Timestamp: now, Nonce: "n-1"}
	signed, err := SignCallback("not-a-real-signing-key", cb)
	if err != nil {
		t.Fatalf("SignCallback: %v", err)
	}
	if err := v.Verify(r, signed, now); !errors.Is(err, ErrUnknownConnector) {
		t.Errorf("Verify error = %v, want ErrUnknownConnector", err)
	}
	noSecret, err := r.AddConnector(Connector{ID: "teams-acme", Kind: KindTeams, Tenant: "acme", Scope: "team:acme"})
	if err != nil {
		t.Fatalf("AddConnector: %v", err)
	}
	cb2 := Callback{ConnectorID: "teams-acme", Timestamp: now, Nonce: "n-2"}
	signed2, err := SignCallback("anything", cb2)
	if err != nil {
		t.Fatalf("SignCallback: %v", err)
	}
	if err := v.Verify(noSecret, signed2, now); !errors.Is(err, ErrNoSecret) {
		t.Errorf("Verify error = %v, want ErrNoSecret", err)
	}
}

func TestSignCallbackRefusesAnEmptySecret(t *testing.T) {
	if _, err := SignCallback("  ", Callback{ConnectorID: "c"}); !errors.Is(err, ErrNoSecret) {
		t.Errorf("SignCallback error = %v, want ErrNoSecret", err)
	}
}

// The signed material binds the connector, the timestamp, the nonce and the body, so
// none of them can be borrowed from another callback.
func TestSignedMaterialBindsEveryPart(t *testing.T) {
	base := Callback{ConnectorID: "slack-acme", Timestamp: now, Nonce: "n-1", Body: []byte("{}")}
	material := SignedMaterial(base)
	for name, altered := range map[string]Callback{
		"connector": {ConnectorID: "slack-other", Timestamp: now, Nonce: "n-1", Body: []byte("{}")},
		"timestamp": {ConnectorID: "slack-acme", Timestamp: now.Add(time.Second), Nonce: "n-1", Body: []byte("{}")},
		"nonce":     {ConnectorID: "slack-acme", Timestamp: now, Nonce: "n-2", Body: []byte("{}")},
		"body":      {ConnectorID: "slack-acme", Timestamp: now, Nonce: "n-1", Body: []byte("{\"a\":1}")},
	} {
		if SignedMaterial(altered) == material {
			t.Errorf("changing the %s did not change the signed material", name)
		}
	}
}

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

// Install a connector, bind an identity, deliver a notice under a policy, and accept a
// signed callback — and confirm the delivery carries only what the policy allows.
func TestHappyPathInstallDeliverAndCallback(t *testing.T) {
	r := registry(t)

	p := Policy{
		AllowFields:    []string{"service", "environment"},
		SecretPatterns: []string{`AKIA[0-9A-Z]{16}`},
		AllowFreeText:  true,
	}
	d, err := r.Deliver(Notice{
		ConnectorID: "slack-acme", Scope: "workspace:acme",
		Title: "Public bucket found",
		Body:  "bucket prod-artifacts exposes AKIAEXAMPLEKEYNOTREAL",
		Fields: []Field{
			{Name: "service", Value: "api"},
			{Name: "environment", Value: "prod"},
			{Name: "internal_note", Value: "not in the policy"},
		},
	}, p)
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if d.Identity != "U0GHOST" {
		t.Errorf("identity = %q, want the bound identity", d.Identity)
	}
	if strings.Contains(d.Body, "AKIAEXAMPLEKEYNOTREAL") {
		t.Error("the access key must not survive delivery")
	}
	if d.Fields[0].Value != "api" || d.Fields[1].Value != "prod" {
		t.Errorf("allowlisted fields = %v, want them sent", d.Fields)
	}
	if d.Fields[2].Value != Redacted {
		t.Errorf("unnamed field = %q, want it redacted", d.Fields[2].Value)
	}
	if !d.Redacted {
		t.Error("the delivery must report that it withheld something")
	}

	cb := Callback{ConnectorID: "slack-acme", Timestamp: now, Nonce: "n-1", Body: []byte(`{"action":"ack"}`)}
	signed, err := SignCallback("not-a-real-signing-key", cb)
	if err != nil {
		t.Fatalf("SignCallback: %v", err)
	}
	v := &Verifier{}
	if err := v.Verify(r, signed, now); err != nil {
		t.Errorf("Verify: %v", err)
	}
	if err := v.Verify(r, signed, now); !errors.Is(err, ErrReplay) {
		t.Errorf("replayed Verify error = %v, want ErrReplay", err)
	}
}
