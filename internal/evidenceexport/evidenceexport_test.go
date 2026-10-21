package evidenceexport

import (
	"errors"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

func record(id string, retainedUntil time.Time) Record {
	return Record{
		ID:            id,
		Tenant:        "acme",
		Kind:          KindAudit,
		Digest:        "rec-" + id,
		CreatedAt:     now.Add(-30 * 24 * time.Hour),
		RetainedUntil: retainedUntil,
	}
}

func store(t *testing.T, records ...Record) Store {
	t.Helper()
	var s Store
	var err error
	for _, r := range records {
		s, err = s.AddRecord(r)
		if err != nil {
			t.Fatalf("AddRecord(%q): %v", r.ID, err)
		}
	}
	s, err = s.AddKey(SigningKey{ID: "key-2025", ValidFrom: now.Add(-365 * 24 * time.Hour)})
	if err != nil {
		t.Fatalf("AddKey: %v", err)
	}
	return s
}

func hold(id string, recordIDs ...string) Hold {
	return Hold{
		ID:        id,
		Tenant:    "acme",
		RecordIDs: recordIDs,
		Reason:    "regulatory investigation into the 2025 pricing change",
		PlacedBy:  "legal",
		PlacedAt:  now.Add(-10 * 24 * time.Hour),
	}
}

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

func TestAddRecordRefusesUnusableRecords(t *testing.T) {
	cases := map[string]struct {
		mutate func(*Record)
		want   error
	}{
		"no identifier":     {func(r *Record) { r.ID = "  " }, ErrNoRecordID},
		"no tenant":         {func(r *Record) { r.Tenant = "" }, ErrNoTenant},
		"no kind":           {func(r *Record) { r.Kind = "" }, ErrNoKind},
		"no retention time": {func(r *Record) { r.RetainedUntil = time.Time{} }, ErrNoRetainedAt},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			r := record("r1", now.Add(24*time.Hour))
			tc.mutate(&r)
			if _, err := (Store{}).AddRecord(r); !errors.Is(err, tc.want) {
				t.Errorf("AddRecord error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestAddRecordRefusesDuplicateIdentifiersWithinATenant(t *testing.T) {
	s, err := store(t, record("r1", now.Add(time.Hour))).AddRecord(record("r1", now.Add(time.Hour)))
	if !errors.Is(err, ErrDuplicateRecord) {
		t.Errorf("AddRecord error = %v, want ErrDuplicateRecord", err)
	}
	_ = s
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

// The export is a manifest of records, not a blob, so a customer can verify what they
// received against what existed.
func TestExportIsScopedAndDigestBound(t *testing.T) {
	s := store(t,
		record("r1", now.Add(time.Hour)),
		record("r2", now.Add(2*time.Hour)),
	)
	other := Record{ID: "r9", Tenant: "other", Kind: KindAudit, Digest: "d", RetainedUntil: now.Add(time.Hour)}
	s, err := s.AddRecord(other)
	if err != nil {
		t.Fatalf("AddRecord: %v", err)
	}
	exp, err := s.Export("acme", now)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if len(exp.Records) != 2 {
		t.Fatalf("exported %d records, want 2", len(exp.Records))
	}
	for _, r := range exp.Records {
		if r.Tenant != "acme" {
			t.Errorf("export leaked another tenant's record %q", r.ID)
		}
	}
	if exp.Digest == "" || DigestRecords(exp.Records) != exp.Digest {
		t.Error("the export digest must bind its records")
	}
}

// The same state always exports the same way, so two exports are comparable.
func TestExportIsDeterministic(t *testing.T) {
	s := store(t, record("r1", now.Add(time.Hour)), record("r2", now.Add(2*time.Hour)))
	first, err := s.Export("acme", now)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	second, err := s.Export("acme", now)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if first.Digest != second.Digest {
		t.Error("two exports of the same state must share a digest")
	}
	if first.Records[0].ID != "r1" {
		t.Error("exported records must be sorted by identifier")
	}
}

// A record past its retention is not exported: a SIEM is a copy of what exists, and
// offering to hand over what the archive has let go of is a promise the archive cannot
// keep.
func TestExportOmitsRecordsPastRetention(t *testing.T) {
	s := store(t,
		record("kept", now.Add(time.Hour)),
		record("expired", now.Add(-time.Hour)),
	)
	exp, err := s.Export("acme", now)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if len(exp.Records) != 1 || exp.Records[0].ID != "kept" {
		t.Errorf("exported %v, want only the retained record", exp.Records)
	}
}

// A hold suspends deletion; it does not hide. Evidence under hold is still exported.
func TestExportIncludesRecordsUnderHold(t *testing.T) {
	s := store(t, record("r1", now.Add(time.Hour)))
	s, err := s.PlaceHold(hold("H1", "r1"))
	if err != nil {
		t.Fatalf("PlaceHold: %v", err)
	}
	exp, err := s.Export("acme", now)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if len(exp.Records) != 1 {
		t.Error("a hold must not hide a record from the export")
	}
}

func TestExportRequiresAScope(t *testing.T) {
	if _, err := store(t).Export("  ", now); !errors.Is(err, ErrNoScope) {
		t.Errorf("Export error = %v, want ErrNoScope", err)
	}
}

// ---------------------------------------------------------------------------
// Signing and rotation
// ---------------------------------------------------------------------------

// A signature records the key and the moment, and the key must have been valid then.
func TestSignRequiresAValidKey(t *testing.T) {
	s := store(t, record("r1", now.Add(time.Hour)))
	exp, err := s.Export("acme", now)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if _, err := s.Sign(exp, "no-such-key", now); !errors.Is(err, ErrNoSigningKey) {
		t.Errorf("Sign with an unknown key = %v, want ErrNoSigningKey", err)
	}
	expired := SigningKey{ID: "old", ValidFrom: now.Add(-48 * time.Hour), ValidUntil: now.Add(-time.Hour)}
	s, err = s.AddKey(expired)
	if err != nil {
		t.Fatalf("AddKey: %v", err)
	}
	if _, err := s.Sign(exp, "old", now); !errors.Is(err, ErrKeyNotValid) {
		t.Errorf("Sign with an expired key = %v, want ErrKeyNotValid", err)
	}
}

func TestSignedExportVerifies(t *testing.T) {
	s := store(t, record("r1", now.Add(time.Hour)))
	exp, err := s.Export("acme", now)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	exp, err = s.Sign(exp, "key-2025", now)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := s.Verify(exp); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

// The load-bearing property: a signature made with a key that has since rotated out
// still verifies. Demanding the signing key be current would reject the oldest
// records in the archive, which are exactly the records an investigation wants.
func TestSignatureSurvivesRotationOfItsKey(t *testing.T) {
	s := store(t, record("r1", now.Add(time.Hour)))
	exp, err := s.Export("acme", now)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	signedAt := now.Add(-24 * time.Hour)
	exp, err = s.Sign(exp, "key-2025", signedAt)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	s, err = s.RotateKey("key-2025", "key-2026", now)
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	if err := s.Verify(exp); err != nil {
		t.Errorf("a signature must survive the rotation of its key: %v", err)
	}
	// And the retired key can no longer sign anything new.
	fresh, err := s.Export("acme", now)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if _, err := s.Sign(fresh, "key-2025", now); !errors.Is(err, ErrKeyNotValid) {
		t.Errorf("signing with a retired key = %v, want ErrKeyNotValid", err)
	}
}

// A key that expires does not retroactively invalidate what it signed either.
func TestSignatureSurvivesExpiryOfItsKey(t *testing.T) {
	s := store(t, record("r1", now.Add(time.Hour)))
	s, err := s.AddKey(SigningKey{ID: "short", ValidFrom: now.Add(-48 * time.Hour), ValidUntil: now.Add(-time.Hour)})
	if err != nil {
		t.Fatalf("AddKey: %v", err)
	}
	exp, err := s.Export("acme", now)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	exp, err = s.Sign(exp, "short", now.Add(-2*time.Hour))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := s.Verify(exp); err != nil {
		t.Errorf("a signature must survive the expiry of its key: %v", err)
	}
}

// Two keys valid at once makes "which key signed this" a question with two answers.
func TestRotationRefusesAnAlreadyValidSuccessor(t *testing.T) {
	s := store(t, record("r1", now.Add(time.Hour)))
	s, err := s.AddKey(SigningKey{ID: "key-2026", ValidFrom: now.Add(-time.Hour)})
	if err != nil {
		t.Fatalf("AddKey: %v", err)
	}
	if _, err := s.RotateKey("key-2025", "key-2026", now); !errors.Is(err, ErrDuplicateKey) {
		t.Errorf("RotateKey error = %v, want ErrDuplicateKey", err)
	}
}

func TestRotationRefusesAnUnknownOrInvalidKey(t *testing.T) {
	s := store(t, record("r1", now.Add(time.Hour)))
	if _, err := s.RotateKey("no-such-key", "new", now); !errors.Is(err, ErrNoSigningKey) {
		t.Errorf("RotateKey error = %v, want ErrNoSigningKey", err)
	}
	if _, err := s.RotateKey("key-2025", "  ", now); !errors.Is(err, ErrNoKeyID) {
		t.Errorf("RotateKey error = %v, want ErrNoKeyID", err)
	}
}

func TestVerifyRefusesUnsignedTamperedAndBrokenExports(t *testing.T) {
	s := store(t, record("r1", now.Add(time.Hour)))
	exp, err := s.Export("acme", now)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if err := s.Verify(exp); !errors.Is(err, ErrUnsigned) {
		t.Errorf("Verify on an unsigned export = %v, want ErrUnsigned", err)
	}
	signed, err := s.Sign(exp, "key-2025", now)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := s.Verify(signed); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	tampered := signed
	tampered.Records = append([]Record(nil), signed.Records...)
	tampered.Records[0].Digest = "tampered"
	if err := s.Verify(tampered); !errors.Is(err, ErrDigestMismatch) {
		t.Errorf("Verify on a tampered export = %v, want ErrDigestMismatch", err)
	}
	badsig := signed
	sig := *signed.Signature
	sig.Value = "sig-not-really"
	badsig.Signature = &sig
	if err := s.Verify(badsig); !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("Verify with a forged signature = %v, want ErrSignatureInvalid", err)
	}
	blank := signed
	blank.Digest = ""
	if err := s.Verify(blank); !errors.Is(err, ErrNoDigest) {
		t.Errorf("Verify with no digest = %v, want ErrNoDigest", err)
	}
	orphan := signed
	orphanSig := *signed.Signature
	orphanSig.KeyID = "no-such-key"
	orphan.Signature = &orphanSig
	if err := s.Verify(orphan); !errors.Is(err, ErrNoSigningKey) {
		t.Errorf("Verify with an unknown key = %v, want ErrNoSigningKey", err)
	}
}

// ---------------------------------------------------------------------------
// Legal holds
// ---------------------------------------------------------------------------

func TestPlaceHoldRequiresIdentifierReasonAndActor(t *testing.T) {
	cases := map[string]struct {
		mutate func(*Hold)
		want   error
	}{
		"no identifier": {func(h *Hold) { h.ID = "" }, ErrNoHoldID},
		"no tenant":     {func(h *Hold) { h.Tenant = "" }, ErrNoTenant},
		"no reason":     {func(h *Hold) { h.Reason = "  " }, ErrNoReason},
		"no actor":      {func(h *Hold) { h.PlacedBy = "" }, ErrNoActor},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h := hold("H1")
			tc.mutate(&h)
			if _, err := (Store{}).PlaceHold(h); !errors.Is(err, tc.want) {
				t.Errorf("PlaceHold error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestPlaceHoldRefusesDuplicateIdentifiers(t *testing.T) {
	s, err := store(t, record("r1", now.Add(time.Hour))).PlaceHold(hold("H1"))
	if err != nil {
		t.Fatalf("PlaceHold: %v", err)
	}
	if _, err := s.PlaceHold(hold("H1")); !errors.Is(err, ErrDuplicateHold) {
		t.Errorf("PlaceHold error = %v, want ErrDuplicateHold", err)
	}
}

// A regulatory investigation arriving after the data would have been deleted is the
// normal case, not the exception.
func TestHoldPlacedAfterRetentionDeadlineStillSuspendsTheSweep(t *testing.T) {
	s := store(t, record("r1", now.Add(-time.Hour))) // already past retention
	s, err := s.PlaceHold(hold("H1", "r1"))
	if err != nil {
		t.Fatalf("PlaceHold: %v", err)
	}
	if _, err := s.Expunge("acme", "r1", now); !errors.Is(err, ErrUnderHold) {
		t.Errorf("Expunge under a late hold = %v, want ErrUnderHold", err)
	}
	if _, err := s.Sweep("acme", now); !errors.Is(err, ErrUnderHold) {
		t.Errorf("Sweep under a late hold = %v, want ErrUnderHold", err)
	}
}

// The hold is evaluated at the moment of the question, so a hold released a moment
// before the sweep runs no longer suspends it.
func TestReleasedHoldNoLongerSuspendsTheSweep(t *testing.T) {
	s := store(t, record("r1", now.Add(-time.Hour)))
	s, err := s.PlaceHold(hold("H1", "r1"))
	if err != nil {
		t.Fatalf("PlaceHold: %v", err)
	}
	s, err = s.ReleaseHold("H1", "legal", "investigation concluded", now)
	if err != nil {
		t.Fatalf("ReleaseHold: %v", err)
	}
	candidates, err := s.Sweep("acme", now)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if len(candidates) != 1 || candidates[0].ID != "r1" {
		t.Errorf("sweep candidates = %v, want the released record", candidates)
	}
}

// Releasing a hold and expunging the record are separate acts. A release destroys
// nothing.
func TestReleaseHoldDoesNotDestroyTheRecord(t *testing.T) {
	s := store(t, record("r1", now.Add(-time.Hour)))
	s, err := s.PlaceHold(hold("H1", "r1"))
	if err != nil {
		t.Fatalf("PlaceHold: %v", err)
	}
	s, err = s.ReleaseHold("H1", "legal", "investigation concluded", now)
	if err != nil {
		t.Fatalf("ReleaseHold: %v", err)
	}
	if _, ok := s.record("acme", "r1"); !ok {
		t.Error("releasing a hold must not destroy the record")
	}
}

func TestReleaseHoldRequiresActorAndReason(t *testing.T) {
	s, err := store(t, record("r1", now.Add(time.Hour))).PlaceHold(hold("H1"))
	if err != nil {
		t.Fatalf("PlaceHold: %v", err)
	}
	if _, err := s.ReleaseHold("H1", "  ", "done", now); !errors.Is(err, ErrNoActor) {
		t.Errorf("ReleaseHold error = %v, want ErrNoActor", err)
	}
	if _, err := s.ReleaseHold("H1", "legal", "  ", now); !errors.Is(err, ErrNoReason) {
		t.Errorf("ReleaseHold error = %v, want ErrNoReason", err)
	}
}

func TestReleaseHoldRefusesUnknownAndRepeatedReleases(t *testing.T) {
	s, err := store(t, record("r1", now.Add(time.Hour))).PlaceHold(hold("H1"))
	if err != nil {
		t.Fatalf("PlaceHold: %v", err)
	}
	if _, err := s.ReleaseHold("no-such-hold", "legal", "done", now); !errors.Is(err, ErrUnknownHold) {
		t.Errorf("ReleaseHold error = %v, want ErrUnknownHold", err)
	}
	s, err = s.ReleaseHold("H1", "legal", "done", now)
	if err != nil {
		t.Fatalf("ReleaseHold: %v", err)
	}
	if _, err := s.ReleaseHold("H1", "legal", "done again", now); !errors.Is(err, ErrHoldAlreadyReleased) {
		t.Errorf("second ReleaseHold error = %v, want ErrHoldAlreadyReleased", err)
	}
}

// A hold with no record list covers the whole tenant.
func TestTenantWideHoldCoversEveryRecord(t *testing.T) {
	s := store(t, record("r1", now.Add(-time.Hour)), record("r2", now.Add(-time.Hour)))
	s, err := s.PlaceHold(hold("H1"))
	if err != nil {
		t.Fatalf("PlaceHold: %v", err)
	}
	if _, err := s.Expunge("acme", "r1", now); !errors.Is(err, ErrUnderHold) {
		t.Errorf("Expunge = %v, want ErrUnderHold", err)
	}
	if _, err := s.Expunge("acme", "r2", now); !errors.Is(err, ErrUnderHold) {
		t.Errorf("Expunge = %v, want ErrUnderHold", err)
	}
}

// A hold for one tenant does not protect another tenant's records.
func TestHoldDoesNotCrossTenants(t *testing.T) {
	s := store(t, record("r1", now.Add(-time.Hour)))
	other := Record{ID: "r9", Tenant: "other", Kind: KindAudit, Digest: "d", RetainedUntil: now.Add(-time.Hour)}
	s, err := s.AddRecord(other)
	if err != nil {
		t.Fatalf("AddRecord: %v", err)
	}
	s, err = s.PlaceHold(hold("H1", "r1"))
	if err != nil {
		t.Fatalf("PlaceHold: %v", err)
	}
	if _, err := s.Expunge("other", "r9", now); err != nil {
		t.Errorf("Expunge of another tenant's record = %v, want it to proceed", err)
	}
}

// ---------------------------------------------------------------------------
// Expungement and sweeps
// ---------------------------------------------------------------------------

func TestExpungeRefusesRecordsWithinRetention(t *testing.T) {
	s := store(t, record("r1", now.Add(time.Hour)))
	if _, err := s.Expunge("acme", "r1", now); !errors.Is(err, ErrNotExpired) {
		t.Errorf("Expunge error = %v, want ErrNotExpired", err)
	}
}

func TestExpungeRefusesUnknownRecords(t *testing.T) {
	s := store(t)
	if _, err := s.Expunge("acme", "nope", now); !errors.Is(err, ErrUnknownRecord) {
		t.Errorf("Expunge error = %v, want ErrUnknownRecord", err)
	}
}

func TestExpungeDeletesAnExpiredUnheldRecord(t *testing.T) {
	s := store(t, record("r1", now.Add(-time.Hour)))
	s, err := s.Expunge("acme", "r1", now)
	if err != nil {
		t.Fatalf("Expunge: %v", err)
	}
	if _, ok := s.record("acme", "r1"); ok {
		t.Error("the record should have been deleted")
	}
}

// A sweep that quietly skips one record and deletes the rest is how an archive ends up
// looking clean and not being.
func TestSweepIsRefusedWholeWhenOneRecordIsHeld(t *testing.T) {
	s := store(t,
		record("r1", now.Add(-time.Hour)),
		record("r2", now.Add(-time.Hour)),
	)
	s, err := s.PlaceHold(hold("H1", "r2"))
	if err != nil {
		t.Fatalf("PlaceHold: %v", err)
	}
	_, sweepErr := s.Sweep("acme", now)
	if !errors.Is(sweepErr, ErrUnderHold) {
		t.Fatalf("Sweep error = %v, want ErrUnderHold", sweepErr)
	}
	if !strings.Contains(sweepErr.Error(), "r2") {
		t.Errorf("the refusal must name the held record, got %v", sweepErr)
	}
	// And nothing was deleted.
	if _, ok := s.record("acme", "r1"); !ok {
		t.Error("a refused sweep must delete nothing")
	}
}

func TestSweepListsCandidatesInOrder(t *testing.T) {
	s := store(t,
		record("r2", now.Add(-time.Hour)),
		record("r1", now.Add(-time.Hour)),
		record("kept", now.Add(time.Hour)),
	)
	candidates, err := s.Sweep("acme", now)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if len(candidates) != 2 || candidates[0].ID != "r1" || candidates[1].ID != "r2" {
		t.Errorf("sweep candidates = %v, want r1 and r2 in order", candidates)
	}
}

// ---------------------------------------------------------------------------
// Closure
// ---------------------------------------------------------------------------

// Closing an account does not release its evidence, and it does not release its holds.
func TestClosureDoesNotReleaseEvidenceOrHolds(t *testing.T) {
	s := store(t, record("r1", now.Add(-time.Hour)))
	s, err := s.PlaceHold(hold("H1", "r1"))
	if err != nil {
		t.Fatalf("PlaceHold: %v", err)
	}
	s, err = s.CloseAccount(now)
	if err != nil {
		t.Fatalf("CloseAccount: %v", err)
	}
	if !s.AccountClosed {
		t.Fatal("the account should be closed")
	}
	if _, ok := s.record("acme", "r1"); !ok {
		t.Error("closure must not destroy evidence")
	}
	if _, err := s.Expunge("acme", "r1", now); !errors.Is(err, ErrUnderHold) {
		t.Errorf("Expunge after closure = %v, want ErrUnderHold", err)
	}
}

// A closed account's evidence is still evidence, and still exportable.
func TestExportAfterClosureStillWorks(t *testing.T) {
	s := store(t, record("r1", now.Add(time.Hour)))
	if _, err := s.ExportAfterClosure("acme", now); !errors.Is(err, ErrAccountClosed) {
		t.Errorf("ExportAfterClosure on an open account = %v, want ErrAccountClosed", err)
	}
	s, err := s.CloseAccount(now)
	if err != nil {
		t.Fatalf("CloseAccount: %v", err)
	}
	exp, err := s.ExportAfterClosure("acme", now)
	if err != nil {
		t.Fatalf("ExportAfterClosure: %v", err)
	}
	if len(exp.Records) != 1 {
		t.Errorf("exported %d records, want 1", len(exp.Records))
	}
}

func TestCloseAccountIsRefusedTwice(t *testing.T) {
	s, err := store(t).CloseAccount(now)
	if err != nil {
		t.Fatalf("CloseAccount: %v", err)
	}
	if _, err := s.CloseAccount(now); !errors.Is(err, ErrAccountClosed) {
		t.Errorf("second CloseAccount error = %v, want ErrAccountClosed", err)
	}
}

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

// Record, export, sign, rotate the key, place a hold, close the account, and verify
// that the export still verifies, the record still exists, and the hold still holds.
func TestHappyPathExportSignRotateHoldClose(t *testing.T) {
	s := store(t, record("r1", now.Add(30*24*time.Hour)), record("r2", now.Add(-time.Hour)))

	exp, err := s.Export("acme", now)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if len(exp.Records) != 1 || exp.Records[0].ID != "r1" {
		t.Fatalf("exported %v, want only the retained record", exp.Records)
	}

	exp, err = s.Sign(exp, "key-2025", now)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := s.Verify(exp); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	s, err = s.RotateKey("key-2025", "key-2026", now.Add(time.Hour))
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	if err := s.Verify(exp); err != nil {
		t.Errorf("the export must still verify after rotation: %v", err)
	}

	// The expired record is swept away, and the hold then protects what is left.
	candidates, err := s.Sweep("acme", now)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if len(candidates) != 1 || candidates[0].ID != "r2" {
		t.Fatalf("sweep candidates = %v, want r2", candidates)
	}
	s, err = s.Expunge("acme", "r2", now)
	if err != nil {
		t.Fatalf("Expunge: %v", err)
	}
	if _, ok := s.record("acme", "r2"); ok {
		t.Error("r2 should have been deleted")
	}

	s, err = s.PlaceHold(hold("H1", "r1"))
	if err != nil {
		t.Fatalf("PlaceHold: %v", err)
	}
	s, err = s.CloseAccount(now.Add(time.Hour))
	if err != nil {
		t.Fatalf("CloseAccount: %v", err)
	}
	if _, err := s.Expunge("acme", "r1", now.Add(60*24*time.Hour)); !errors.Is(err, ErrUnderHold) {
		t.Errorf("Expunge after closure = %v, want ErrUnderHold", err)
	}
	if err := s.Verify(exp); err != nil {
		t.Errorf("the export must still verify after everything: %v", err)
	}
}
