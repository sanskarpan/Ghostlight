// Package evidenceexport governs the export of audit and evidence records to a SIEM,
// the signing of those exports, the retention of the records themselves, and the legal
// holds that suspend retention.
//
// Four problems live here, and each has a trap that makes the obvious implementation
// wrong.
//
// The first is signing. An export that is signed with a key that has since rotated must
// still verify, because the export was made when the key was valid and the signature
// attests to that moment — not to the key's state now. A verifier that demands the
// signing key be current will reject the oldest records in the archive, which are
// exactly the records an investigation wants. So a signature carries the key it was
// made with and the moment it was made, and verification asks only whether that key
// was valid at that moment. Rotation therefore does not retroactively invalidate
// anything, and expiry does not either.
//
// The second is retention. A record past its retention age should be deleted, but a
// record under legal hold must not be, and the interaction is where the damage happens:
// a hold applied after the retention deadline arrived, or a hold released a moment
// before the sweep ran. A hold is therefore evaluated at the moment of deletion, not
// cached at the moment it was applied, and a delete that would touch a held record is
// refused rather than performed partially.
//
// The third is that a hold must not be lifted by the person who benefits from the
// evidence disappearing. Releasing a hold and expunging the record are separate acts,
// and a release that also destroys the record is a release with an ulterior motive
// wearing a legitimate costume.
//
// The fourth is closure. Closing an account does not release its evidence. The records
// survive their retention profile, and their holds survive their account — a hold
// outliving the tenant is the normal case, not an edge case, because a regulatory
// investigation outlives the company it was launched against.
//
// Everything this package emits is bounded and deterministic. An export is a manifest
// of records, not a blob, so a customer can verify what they received against what
// existed; and the same records always export in the same order with the same digest,
// so two exports of the same state are comparable.
package evidenceexport

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Errors returned by this package's export and retention rules.
var (
	// ErrNoRecordID means a record carries no identifier. Records are keyed by
	// identifier, and an export of unnamed records cannot be reconciled against
	// anything.
	ErrNoRecordID = errors.New("evidence record must carry an identifier")
	// ErrDuplicateRecord means two records share an identifier.
	ErrDuplicateRecord = errors.New("evidence record identifier is already in use")
	// ErrNoKind means a record carries no kind. A SIEM's schema is built on kind, and
	// an untyped record is one the collector cannot place.
	ErrNoKind = errors.New("evidence record must carry a kind")
	// ErrNoRetainedAt means a record carries no retention timestamp.
	ErrNoRetainedAt = errors.New("evidence record must carry a retention timestamp")
	// ErrNoTenant means a record carries no tenant. Exports are scoped to a tenant,
	// and an unowned record would be exported to whoever asks.
	ErrNoTenant = errors.New("evidence record must carry a tenant")
	// ErrNoKeyID means a signing key carries no identifier.
	ErrNoKeyID = errors.New("signing key must carry an identifier")
	// ErrDuplicateKey means two signing keys share an identifier.
	ErrDuplicateKey = errors.New("signing key identifier is already in use")
	// ErrKeyNotValid means a signing key is outside its own validity window.
	ErrKeyNotValid = errors.New("signing key is not valid at that moment")
	// ErrNoSigningKey means an export was signed with no key, or referenced a key
	// that does not exist.
	ErrNoSigningKey = errors.New("export does not name a valid signing key")
	// ErrNoDigest means an export carries no digest. A manifest without a digest
	// cannot be checked against what was sent.
	ErrNoDigest = errors.New("export must carry a digest")
	// ErrDigestMismatch means the export's records do not digest to its recorded
	// digest.
	ErrDigestMismatch = errors.New("export digest does not match its records")
	// ErrSignatureInvalid means a signature does not verify against the key and
	// moment it claims.
	ErrSignatureInvalid = errors.New("export signature does not verify")
	// ErrUnsigned means an export carries no signature.
	ErrUnsigned = errors.New("export is unsigned")
	// ErrNoReason means an act with consequences carried no reason. Holds, releases
	// and expungements all need one; six weeks later, an unexplained one cannot be
	// told apart from a mistake.
	ErrNoReason = errors.New("reason must be stated")
	// ErrNoHoldID means a hold carries no identifier.
	ErrNoHoldID = errors.New("legal hold must carry an identifier")
	// ErrDuplicateHold means two holds share an identifier.
	ErrDuplicateHold = errors.New("legal hold identifier is already in use")
	// ErrUnknownHold means a release names a hold that does not exist.
	ErrUnknownHold = errors.New("no such legal hold")
	// ErrHoldAlreadyReleased means a hold was released twice.
	ErrHoldAlreadyReleased = errors.New("legal hold is already released")
	// ErrNoActor means an act with consequences named no actor.
	ErrNoActor = errors.New("act must name an actor")
	// ErrHoldNotApplies means a hold was applied to a record it does not cover.
	ErrHoldNotApplies = errors.New("legal hold does not apply to that record")
	// ErrUnderHold means a deletion would touch a record under legal hold. The
	// sweep is refused rather than performed partially, because a partially applied
	// sweep leaves the archive in a state nobody can describe.
	ErrUnderHold = errors.New("record is under legal hold")
	// ErrExpired means a record is past its retention age.
	ErrExpired = errors.New("record is past its retention age")
	// ErrNotExpired means a record is still within its retention age.
	ErrNotExpired = errors.New("record is within its retention age")
	// ErrUnknownRecord means an act names a record that does not exist.
	ErrUnknownRecord = errors.New("no such evidence record")
	// ErrNoScope means an export named no tenant to export.
	ErrNoScope = errors.New("export must name a tenant to export")
	// ErrMaxRecords means an export would exceed MaxRecords. A bounded export is
	// refused rather than truncated, because a truncated export that looks complete
	// is an export that silently omits the record nobody was looking for.
	ErrMaxRecords = errors.New("export exceeds the record bound")
	// ErrMaxHolds means a tenant already has MaxHolds legal holds in force. More
	// than that is not a legal practice worth supporting, and a limit that is
	// never reached is not a limit.
	ErrMaxHolds = errors.New("tenant exceeds the legal hold bound")
	// ErrAccountClosed means an act requires an open account.
	ErrAccountClosed = errors.New("account is closed")
)

// Bounds on an export.
const (
	// MaxRecords is the largest number of records one export may carry.
	MaxRecords = 10000
	// MaxHolds is the largest number of legal holds that may be in force at once
	// against one tenant.
	MaxHolds = 1000
)

// RecordKind names what a record is, for the SIEM's schema.
type RecordKind string

const (
	// KindAudit is an audit trail entry.
	KindAudit RecordKind = "audit"
	// KindEvidence is an evidence artefact, such as a signed test run.
	KindEvidence RecordKind = "evidence"
	// KindFinding is a recorded finding against a resource.
	KindFinding RecordKind = "finding"
)

// Record is one exportable evidence record.
type Record struct {
	// ID identifies the record within its tenant.
	ID string
	// Tenant is the owning tenant. Exports are scoped to a tenant, and a record
	// with no tenant would be exported to whoever asked.
	Tenant string
	// Kind says what the record is.
	Kind RecordKind
	// Digest is the record's own content digest, as produced when it was written.
	Digest string
	// CreatedAt is when the record was produced.
	CreatedAt time.Time
	// RetainedUntil is when the record's retention profile says it may be
	// deleted. A record past this point is eligible; it is not deleted until a
	// sweep runs and no hold forbids it.
	RetainedUntil time.Time
}

// SigningKey is a key used to sign exports.
type SigningKey struct {
	// ID identifies the key.
	ID string
	// ValidFrom is when the key became usable.
	ValidFrom time.Time
	// ValidUntil is when the key stopped being usable. A key with a zero
	// ValidUntil is still usable.
	ValidUntil time.Time
}

// ValidAt reports whether the key could be used to sign at the given moment.
func (k SigningKey) ValidAt(at time.Time) bool {
	if at.Before(k.ValidFrom) {
		return false
	}
	if !k.ValidUntil.IsZero() && !at.Before(k.ValidUntil) {
		return false
	}
	return true
}

// Signature is an export's signature.
type Signature struct {
	// KeyID is the key the export was signed with. It is recorded rather than
	// resolved, because the key may since have rotated.
	KeyID string
	// SignedAt is when the export was signed. Verification asks whether the key
	// was valid at this moment, not whether it is valid now.
	SignedAt time.Time
	// Value is the signature itself.
	Value string
}

// Export is a manifest of records sent to a SIEM.
type Export struct {
	// Tenant is the tenant the export covers.
	Tenant string
	// Records are the exported records, sorted by identifier.
	Records []Record
	// Digest binds the records, so a customer can check what they received against
	// what existed.
	Digest string
	// Signature is the export's signature, once signed.
	Signature *Signature
	// CreatedAt is when the export was produced.
	CreatedAt time.Time
}

// Hold is a legal hold suspending retention against the records it covers.
type Hold struct {
	// ID identifies the hold.
	ID string
	// Tenant is the tenant the hold applies to.
	Tenant string
	// RecordIDs are the records the hold covers. An empty list covers the whole
	// tenant, which is the common case for a regulatory investigation.
	RecordIDs []string
	// Reason states why the hold was placed. A hold without one cannot be
	// defended, and cannot be released by anyone who knows what it was for.
	Reason string
	// PlacedBy names who placed it.
	PlacedBy string
	// PlacedAt is when it was placed.
	PlacedAt time.Time
	// ReleasedAt is when it was released; zero while it is in force.
	ReleasedAt time.Time
	// ReleasedBy names who released it; empty while it is in force.
	ReleasedBy string
	// ReleaseReason states why it was released.
	ReleaseReason string
}

// InForce reports whether the hold still suspends retention.
func (h Hold) InForce() bool { return h.ReleasedAt.IsZero() }

// Covers reports whether the hold covers the given record.
func (h Hold) Covers(r Record) bool {
	if h.Tenant != r.Tenant {
		return false
	}
	if len(h.RecordIDs) == 0 {
		return true
	}
	for _, id := range h.RecordIDs {
		if id == r.ID {
			return true
		}
	}
	return false
}

// Store is the set of records, keys, holds and account state.
type Store struct {
	// Records are the stored evidence records.
	Records []Record
	// Keys are the signing keys, including retired ones. A retired key stays in
	// the store, because a signature made with it must still verify.
	Keys []SigningKey
	// Holds are the legal holds, released ones included.
	Holds []Hold
	// AccountClosed reports whether the account has been closed. Closure does not
	// release evidence or holds.
	AccountClosed bool
}

// key looks a signing key up by identifier.
func (s Store) key(id string) (SigningKey, bool) {
	for _, k := range s.Keys {
		if k.ID == id {
			return k, true
		}
	}
	return SigningKey{}, false
}

// record looks a record up by identifier within a tenant.
func (s Store) record(tenant, id string) (Record, bool) {
	for _, r := range s.Records {
		if r.Tenant == tenant && r.ID == id {
			return r, true
		}
	}
	return Record{}, false
}

// held reports whether a record is covered by a hold in force at the given moment.
//
// The hold is evaluated at the moment of the question rather than at the moment it
// was applied, which is the whole point: a hold applied after a retention deadline
// arrived still suspends the sweep, and a hold released a moment before the sweep
// runs no longer does.
func (s Store) held(r Record, at time.Time) (Hold, bool) {
	for _, h := range s.Holds {
		if !h.InForce() {
			continue
		}
		if h.PlacedAt.After(at) {
			continue
		}
		if h.Covers(r) {
			return h, true
		}
	}
	return Hold{}, false
}

// AddRecord stores an evidence record.
func (s Store) AddRecord(r Record) (Store, error) {
	if strings.TrimSpace(r.ID) == "" {
		return s, ErrNoRecordID
	}
	if strings.TrimSpace(r.Tenant) == "" {
		return s, ErrNoTenant
	}
	if strings.TrimSpace(string(r.Kind)) == "" {
		return s, ErrNoKind
	}
	if r.RetainedUntil.IsZero() {
		return s, ErrNoRetainedAt
	}
	for _, existing := range s.Records {
		if existing.Tenant == r.Tenant && existing.ID == r.ID {
			return s, fmt.Errorf("%w: %q", ErrDuplicateRecord, r.ID)
		}
	}
	s.Records = append(s.Records, r)
	return s, nil
}

// AddKey stores a signing key. Retired keys are kept: a signature made with one must
// still verify long after the key stopped being usable for new signatures.
func (s Store) AddKey(k SigningKey) (Store, error) {
	if strings.TrimSpace(k.ID) == "" {
		return s, ErrNoKeyID
	}
	for _, existing := range s.Keys {
		if existing.ID == k.ID {
			return s, fmt.Errorf("%w: %q", ErrDuplicateKey, k.ID)
		}
	}
	s.Keys = append(s.Keys, k)
	return s, nil
}

// RotateKey retires a key and installs its successor, atomically.
//
// Rotation is refused if the successor is already valid, because two keys valid at
// once makes "which key signed this" a question with two answers, and every signature
// made afterwards would be ambiguous.
func (s Store) RotateKey(oldID, newID string, at time.Time) (Store, error) {
	old, ok := s.key(oldID)
	if !ok {
		return s, fmt.Errorf("%w: %q", ErrNoSigningKey, oldID)
	}
	if strings.TrimSpace(newID) == "" {
		return s, ErrNoKeyID
	}
	if _, exists := s.key(newID); exists {
		return s, fmt.Errorf("%w: %q", ErrDuplicateKey, newID)
	}
	if !old.ValidAt(at) {
		return s, fmt.Errorf("%w: %q at %s", ErrKeyNotValid, oldID, at.UTC().Format(time.RFC3339))
	}
	for i := range s.Keys {
		if s.Keys[i].ID == oldID {
			s.Keys[i].ValidUntil = at
		}
	}
	s.Keys = append(s.Keys, SigningKey{ID: newID, ValidFrom: at})
	return s, nil
}

// Export produces a manifest of the tenant's records that are within retention.
//
// Records past their retention are not exported: a SIEM is a copy of what exists, and
// offering to hand over records the archive has already let go of would be a promise
// the archive cannot keep. Records under hold are exported — a hold suspends deletion,
// it does not hide.
func (s Store) Export(tenant string, at time.Time) (Export, error) {
	if strings.TrimSpace(tenant) == "" {
		return Export{}, ErrNoScope
	}
	var records []Record
	for _, r := range s.Records {
		if r.Tenant != tenant {
			continue
		}
		if !r.RetainedUntil.After(at) {
			continue
		}
		records = append(records, r)
	}
	if len(records) > MaxRecords {
		return Export{}, fmt.Errorf("%w: %d records exceeds the maximum of %d", ErrMaxRecords, len(records), MaxRecords)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	exp := Export{Tenant: tenant, Records: records, CreatedAt: at}
	exp.Digest = DigestRecords(records)
	return exp, nil
}

// DigestRecords computes the manifest digest over a set of records.
//
// The digest is over the record identifiers and their own digests, not over the export
// as a byte stream, so it is stable across a re-serialization and a customer can
// recompute it from the records they received.
func DigestRecords(records []Record) string {
	sorted := make([]Record, len(records))
	copy(sorted, records)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	h := sha256.New()
	for _, r := range sorted {
		fmt.Fprintf(h, "%s|%s|%s|%s|%s\n", r.Tenant, r.ID, r.Kind, r.Digest, r.RetainedUntil.UTC().Format(time.RFC3339))
	}
	return "export-" + hex.EncodeToString(h.Sum(nil))[:32]
}

// Sign signs an export with the named key.
//
// The signature records the key and the moment, and the key must have been valid at
// that moment. Verification then asks only whether the key was valid when the export
// was made — which is what makes a signature survive both the rotation and the expiry
// of its key.
func (s Store) Sign(exp Export, keyID string, at time.Time) (Export, error) {
	k, ok := s.key(keyID)
	if !ok {
		return exp, fmt.Errorf("%w: %q", ErrNoSigningKey, keyID)
	}
	if !k.ValidAt(at) {
		return exp, fmt.Errorf("%w: %q at %s", ErrKeyNotValid, keyID, at.UTC().Format(time.RFC3339))
	}
	value := signValue(exp.Digest, keyID, at)
	exp.Signature = &Signature{KeyID: keyID, SignedAt: at, Value: value}
	return exp, nil
}

// signValue computes the signature over the digest, the key and the moment.
func signValue(digest, keyID string, at time.Time) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%s", digest, keyID, at.UTC().Format(time.RFC3339))
	return "sig-" + hex.EncodeToString(h.Sum(nil))[:32]
}

// Verify checks an export's digest and signature.
//
// The key is looked up by the identifier the signature carries, and is required to
// have been valid at the signing moment rather than now. A key that has since rotated
// out or expired does not invalidate a signature made while it was good — demanding
// otherwise would reject the oldest records in the archive, which are exactly the
// records an investigation wants.
func (s Store) Verify(exp Export) error {
	if exp.Digest == "" {
		return ErrNoDigest
	}
	if DigestRecords(exp.Records) != exp.Digest {
		return ErrDigestMismatch
	}
	if exp.Signature == nil {
		return ErrUnsigned
	}
	k, ok := s.key(exp.Signature.KeyID)
	if !ok {
		return fmt.Errorf("%w: %q", ErrNoSigningKey, exp.Signature.KeyID)
	}
	if !k.ValidAt(exp.Signature.SignedAt) {
		return fmt.Errorf("%w: %q at %s", ErrKeyNotValid, k.ID, exp.Signature.SignedAt.UTC().Format(time.RFC3339))
	}
	if signValue(exp.Digest, exp.Signature.KeyID, exp.Signature.SignedAt) != exp.Signature.Value {
		return ErrSignatureInvalid
	}
	return nil
}

// PlaceHold places a legal hold against a tenant's records.
//
// A hold placed after a record's retention deadline has arrived still suspends the
// sweep. That is the case the whole design turns on: a regulatory investigation
// arriving after the data would have been deleted is the normal case, not the
// exception.
func (s Store) PlaceHold(h Hold) (Store, error) {
	if strings.TrimSpace(h.ID) == "" {
		return s, ErrNoHoldID
	}
	if strings.TrimSpace(h.Tenant) == "" {
		return s, ErrNoTenant
	}
	if strings.TrimSpace(h.Reason) == "" {
		return s, ErrNoReason
	}
	if strings.TrimSpace(h.PlacedBy) == "" {
		return s, ErrNoActor
	}
	for _, existing := range s.Holds {
		if existing.ID == h.ID {
			return s, fmt.Errorf("%w: %q", ErrDuplicateHold, h.ID)
		}
	}
	inForce := 0
	for _, existing := range s.Holds {
		if existing.Tenant == h.Tenant && existing.InForce() {
			inForce++
		}
	}
	if inForce >= MaxHolds {
		return s, fmt.Errorf("%w: %d holds already in force for %q", ErrMaxHolds, inForce, h.Tenant)
	}
	s.Holds = append(s.Holds, h)
	return s, nil
}

// ReleaseHold releases a legal hold.
//
// Releasing a hold and expunging the record are separate acts. A release destroys
// nothing: the records remain, and a sweep will collect them when their retention
// allows. The two were separate because a release that also destroyed the evidence
// would be a release with an ulterior motive wearing a legitimate costume.
func (s Store) ReleaseHold(id, actor, reason string, at time.Time) (Store, error) {
	if strings.TrimSpace(actor) == "" {
		return s, ErrNoActor
	}
	if strings.TrimSpace(reason) == "" {
		return s, ErrNoReason
	}
	for i := range s.Holds {
		if s.Holds[i].ID != id {
			continue
		}
		if !s.Holds[i].InForce() {
			return s, fmt.Errorf("%w: %q", ErrHoldAlreadyReleased, id)
		}
		s.Holds[i].ReleasedAt = at
		s.Holds[i].ReleasedBy = actor
		s.Holds[i].ReleaseReason = reason
		return s, nil
	}
	return s, fmt.Errorf("%w: %q", ErrUnknownHold, id)
}

// Expunge deletes a record that is past its retention age and not under hold.
//
// The whole sweep is refused if any record would be touched by a hold, rather than
// deleting the eligible records and leaving the held one behind. A partially applied
// sweep leaves the archive in a state nobody can describe, and an archive in an
// indescribable state is one that cannot be audited.
func (s Store) Expunge(tenant, recordID string, at time.Time) (Store, error) {
	r, ok := s.record(tenant, recordID)
	if !ok {
		return s, fmt.Errorf("%w: %q", ErrUnknownRecord, recordID)
	}
	if r.RetainedUntil.After(at) {
		return s, fmt.Errorf("%w: %q until %s", ErrNotExpired, recordID, r.RetainedUntil.UTC().Format(time.RFC3339))
	}
	if h, held := s.held(r, at); held {
		return s, fmt.Errorf("%w: %q under hold %q", ErrUnderHold, recordID, h.ID)
	}
	for i := range s.Records {
		if s.Records[i].Tenant == tenant && s.Records[i].ID == recordID {
			s.Records = append(s.Records[:i], s.Records[i+1:]...)
			return s, nil
		}
	}
	return s, fmt.Errorf("%w: %q", ErrUnknownRecord, recordID)
}

// Sweep returns the records a sweep would delete at the given moment, and refuses to
// describe a partial sweep.
//
// Every candidate is checked against the holds in force. If any candidate is held, the
// sweep is refused in full and the held record is named, because a sweep that quietly
// skips one record and deletes the rest is how an archive ends up in a state that
// looks clean and is not.
func (s Store) Sweep(tenant string, at time.Time) ([]Record, error) {
	if strings.TrimSpace(tenant) == "" {
		return nil, ErrNoScope
	}
	var candidates []Record
	for _, r := range s.Records {
		if r.Tenant != tenant {
			continue
		}
		if r.RetainedUntil.After(at) {
			continue
		}
		if h, held := s.held(r, at); held {
			return nil, fmt.Errorf("%w: %q under hold %q", ErrUnderHold, r.ID, h.ID)
		}
		candidates = append(candidates, r)
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].ID < candidates[j].ID })
	return candidates, nil
}

// CloseAccount closes the account.
//
// Closure does not release evidence, and it does not release holds. A hold outliving
// the tenant is the normal case, because a regulatory investigation outlives the
// company it was launched against. The records survive their retention profile and
// the holds survive the account, and only an explicit release changes that.
func (s Store) CloseAccount(at time.Time) (Store, error) {
	if s.AccountClosed {
		return s, fmt.Errorf("%w: already closed", ErrAccountClosed)
	}
	s.AccountClosed = true
	return s, nil
}

// ExportAfterClosure still works, because a closed account's evidence is still
// evidence.
func (s Store) ExportAfterClosure(tenant string, at time.Time) (Export, error) {
	if !s.AccountClosed {
		return Export{}, fmt.Errorf("%w: still open", ErrAccountClosed)
	}
	return s.Export(tenant, at)
}
