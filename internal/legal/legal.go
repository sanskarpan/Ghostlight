// Package legal scopes the platform's legal and privacy obligations by the
// customer's jurisdiction, and refuses to let an organisation launch without the
// documents, owners and accepted versions its jurisdiction requires.
//
// This package exists because of one asymmetry. **The framework is determined by the
// customer's jurisdiction, not by the platform's region.** Ghostlight runs in one AWS
// region, and a customer in the EEA, one in the United Kingdom, one in California and
// one in a country we have not analysed are all served from that same region. They do
// not all owe the same things, and a platform that picks one framework for everyone is
// either over-claiming compliance to some of them or under-claiming it to the rest.
//
// So the scoping is explicit, and the load-bearing rule is that **there is no
// default**. A jurisdiction this package has not been given a framework for is refused
// rather than served from a baseline. The baseline exists, and it is a real document
// set — but it is not a substitute for an analysis, and pretending otherwise is how an
// unanalysed country ends up quietly handled by whichever regime happened to be
// implemented last. Refusing is inconvenient; the alternative is a compliance claim
// nobody checked.
//
// The second rule is that **an obligation cannot be satisfied by a document nobody
// accepted.** The review compares the version each organisation accepted against the
// version currently published, and refuses a stale acceptance. Accepting version 1 of
// a privacy notice that has since become version 3 is not consent to version 3, and a
// consent record that is quietly out of date is worse than no consent record, because
// it looks like an answer.
//
// The third rule is that **a duty without a named owner is an open obligation.** The
// review refuses a launch whose jurisdiction requires a data protection officer, a
// breach owner or a rights-request owner and cannot name one. "The team" is not an
// owner, because a duty that is everybody's is owned by nobody, and a duty owned by
// nobody is a duty that is met whenever somebody remembers.
//
// The fourth rule is that **deadlines are computed, not remembered.** A rights request
// has a statutory response period and a breach has a notification period, and both
// differ by framework. The deadlines are derived from the framework so that an overdue
// request is detected by arithmetic rather than by someone noticing. A deadline that
// lives in a document is a deadline that is met until the first busy week.
//
// And the fifth rule is that **the platform's region does not move the framework.**
// A region is where infrastructure runs; a jurisdiction is where the customer is
// established. They are different facts and the code keeps them apart, because
// conflating them is the mistake that produces a compliance posture for the wrong
// country.
package legal

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Errors returned by this package's legal rules.
var (
	// ErrUnknownJurisdiction means a jurisdiction has no framework. There is no
	// default, because a default is an unanalysed country handled by whichever
	// regime happened to be implemented last.
	ErrUnknownJurisdiction = errors.New("no legal framework for that jurisdiction")
	// ErrNoJurisdiction means an organisation declared no jurisdiction.
	ErrNoJurisdiction = errors.New("organization must declare a jurisdiction")
	// ErrNoArtifactVersion means an accepted document carries no version.
	ErrNoArtifactVersion = errors.New("accepted document must carry a version")
	// ErrStaleAcceptance means an organisation accepted a superseded version of a
	// document. Accepting version 1 of a notice that is now version 3 is not
	// consent to version 3.
	ErrStaleAcceptance = errors.New("accepted document version is superseded")
	// ErrNoArtifact means a required document was not accepted at all.
	ErrNoArtifact = errors.New("required legal document was not accepted")
	// ErrNoOwner means a required duty has no named owner. A duty that is
	// everybody's is owned by nobody.
	ErrNoOwner = errors.New("a required duty has no named owner")
	// ErrNoOwnerName means an owner record carries no name.
	ErrNoOwnerName = errors.New("owner must be a name")
	// ErrUnknownDuty means an owner record names a duty that is not required by
	// any framework.
	ErrUnknownDuty = errors.New("no such duty")
	// ErrNoRequestKind means a rights request names no kind.
	ErrNoRequestKind = errors.New("rights request must carry a kind")
	// ErrUnknownRequestKind means a rights request names a kind the platform does
	// not handle.
	ErrUnknownRequestKind = errors.New("no such rights request kind")
	// ErrNoDetectionTime means a breach record carries no detection time.
	ErrNoDetectionTime = errors.New("breach must carry a detection time")
)

// Jurisdiction is where a customer is established. It is not the platform's region.
type Jurisdiction string

const (
	// JurisdictionGlobal is the baseline for customers in a jurisdiction with no
	// additional regime. It is a real set of obligations, and it is not a
	// substitute for an analysis.
	JurisdictionGlobal Jurisdiction = "global"
	// JurisdictionEU is the European Economic Area.
	JurisdictionEU Jurisdiction = "eu"
	// JurisdictionUK is the United Kingdom.
	JurisdictionUK Jurisdiction = "uk"
	// JurisdictionUSCA is California.
	JurisdictionUSCA Jurisdiction = "us-ca"
	// JurisdictionUSOther is the United States outside California.
	JurisdictionUSOther Jurisdiction = "us-other"
)

// Duty is an obligation that needs a named, accountable owner.
type Duty string

const (
	// DutyDataProtectionOfficer is the EU and UK data protection officer.
	DutyDataProtectionOfficer Duty = "data-protection-officer"
	// DutySecurityIncident owns security incident response.
	DutySecurityIncident Duty = "security-incident"
	// DutyPrivacyRights owns rights requests.
	DutyPrivacyRights Duty = "privacy-rights"
	// DutySubprocessorManagement owns the subprocessor list and its changes.
	DutySubprocessorManagement Duty = "subprocessor-management"
	// DutyLegalReview owns the legal documents themselves.
	DutyLegalReview Duty = "legal-review"
	// DutyOnCall is the operational escalation duty.
	DutyOnCall Duty = "on-call"
)

// ArtifactKind identifies a legal document.
type ArtifactKind string

const (
	// ArtifactTerms is the terms of service.
	ArtifactTerms ArtifactKind = "terms"
	// ArtifactPrivacyNotice is the privacy notice.
	ArtifactPrivacyNotice ArtifactKind = "privacy-notice"
	// ArtifactDPA is the data processing agreement.
	ArtifactDPA ArtifactKind = "dpa"
	// ArtifactSubprocessorList is the subprocessor disclosure.
	ArtifactSubprocessorList ArtifactKind = "subprocessor-list"
	// ArtifactBreachRunbook is the incident notification runbook.
	ArtifactBreachRunbook ArtifactKind = "breach-runbook"
	// ArtifactRetentionSchedule is the published retention schedule.
	ArtifactRetentionSchedule ArtifactKind = "retention-schedule"
)

// Artifact is a published legal document.
type Artifact struct {
	// Kind identifies the document.
	Kind ArtifactKind
	// Version is its version.
	Version string
	// PublishedAt is when this version was published.
	PublishedAt time.Time
}

// Acceptance records that an organisation accepted a version of a document.
type Acceptance struct {
	// Kind identifies the document.
	Kind ArtifactKind
	// Version is the version accepted.
	Version string
	// AcceptedAt is when.
	AcceptedAt time.Time
	// AcceptedBy names who accepted it.
	AcceptedBy string
}

// Owner is a named, accountable owner of a duty.
type Owner struct {
	// Duty is the duty owned.
	Duty Duty
	// Name is the person accountable.
	Name string
	// Team is the team they belong to.
	Team string
	// NamedAt is when they took the duty.
	NamedAt time.Time
}

// Framework is the set of obligations a jurisdiction carries.
type Framework struct {
	// Jurisdiction is the jurisdiction the framework applies to.
	Jurisdiction Jurisdiction
	// Name identifies the framework in documents.
	Name string
	// RequiresDPA reports whether a data processing agreement is required.
	RequiresDPA bool
	// RequiresDPAReports whether a list of processing activities and a transfer
	// mechanism are required.
	RequiresTransferMechanism bool
	// RequiresDPO reports whether a data protection officer is required.
	RequiresDPO bool
	// RequiresRetentionSchedule reports whether a published retention schedule is
	// required.
	RequiresRetentionSchedule bool
	// RightsResponseDays is the period a rights request must be answered in.
	RightsResponseDays int
	// BreachNotificationHours is the period a notifiable breach must be reported
	// in. Zero means the framework sets no statutory period and the baseline
	// applies.
	BreachNotificationHours int
	// RequiredDuties are the duties that must have a named owner.
	RequiredDuties []Duty
	// RequiredArtifacts are the documents that must be accepted.
	RequiredArtifacts []ArtifactKind
}

// frameworks are the analysed jurisdictions.
//
// This table is the whole point of the package, and it is deliberately short. A
// jurisdiction that is not here has not been analysed, and an unanalysed jurisdiction
// is refused rather than served from the nearest row.
var frameworks = map[Jurisdiction]Framework{
	JurisdictionGlobal: {
		Jurisdiction:              JurisdictionGlobal,
		Name:                      "Global baseline",
		RequiresRetentionSchedule: true,
		RightsResponseDays:        30,
		BreachNotificationHours:   24 * 30,
		RequiredDuties: []Duty{
			DutyLegalReview, DutyPrivacyRights, DutySubprocessorManagement, DutyOnCall,
		},
		RequiredArtifacts: []ArtifactKind{
			ArtifactTerms, ArtifactPrivacyNotice, ArtifactSubprocessorList,
			ArtifactBreachRunbook, ArtifactRetentionSchedule,
		},
	},
	JurisdictionEU: {
		Jurisdiction:              JurisdictionEU,
		Name:                      "GDPR (EEA)",
		RequiresDPA:               true,
		RequiresTransferMechanism: true,
		RequiresDPO:               true,
		RequiresRetentionSchedule: true,
		RightsResponseDays:        30,
		BreachNotificationHours:   72,
		RequiredDuties: []Duty{
			DutyDataProtectionOfficer, DutyLegalReview, DutyPrivacyRights,
			DutySubprocessorManagement, DutySecurityIncident, DutyOnCall,
		},
		RequiredArtifacts: []ArtifactKind{
			ArtifactTerms, ArtifactPrivacyNotice, ArtifactDPA, ArtifactSubprocessorList,
			ArtifactBreachRunbook, ArtifactRetentionSchedule,
		},
	},
	JurisdictionUK: {
		Jurisdiction:              JurisdictionUK,
		Name:                      "UK GDPR and DPA 2018",
		RequiresDPA:               true,
		RequiresTransferMechanism: true,
		RequiresDPO:               true,
		RequiresRetentionSchedule: true,
		RightsResponseDays:        30,
		BreachNotificationHours:   72,
		RequiredDuties: []Duty{
			DutyDataProtectionOfficer, DutyLegalReview, DutyPrivacyRights,
			DutySubprocessorManagement, DutySecurityIncident, DutyOnCall,
		},
		RequiredArtifacts: []ArtifactKind{
			ArtifactTerms, ArtifactPrivacyNotice, ArtifactDPA, ArtifactSubprocessorList,
			ArtifactBreachRunbook, ArtifactRetentionSchedule,
		},
	},
	JurisdictionUSCA: {
		Jurisdiction:              JurisdictionUSCA,
		Name:                      "CCPA/CPRA",
		RequiresRetentionSchedule: true,
		RightsResponseDays:        45,
		BreachNotificationHours:   24 * 30,
		RequiredDuties: []Duty{
			DutyLegalReview, DutyPrivacyRights, DutySubprocessorManagement, DutyOnCall,
		},
		RequiredArtifacts: []ArtifactKind{
			ArtifactTerms, ArtifactPrivacyNotice, ArtifactSubprocessorList,
			ArtifactBreachRunbook, ArtifactRetentionSchedule,
		},
	},
	JurisdictionUSOther: {
		Jurisdiction:              JurisdictionUSOther,
		Name:                      "United States baseline",
		RequiresRetentionSchedule: true,
		RightsResponseDays:        45,
		BreachNotificationHours:   24 * 30,
		RequiredDuties: []Duty{
			DutyLegalReview, DutyPrivacyRights, DutySubprocessorManagement, DutyOnCall,
		},
		RequiredArtifacts: []ArtifactKind{
			ArtifactTerms, ArtifactPrivacyNotice, ArtifactSubprocessorList,
			ArtifactBreachRunbook, ArtifactRetentionSchedule,
		},
	},
}

// FrameworkFor returns the framework for a jurisdiction.
//
// There is no fallback. A jurisdiction that is not in the table is refused, because
// the alternative is a country handled by whichever regime happened to be implemented
// last, and a compliance claim nobody made is still a claim.
func FrameworkFor(j Jurisdiction) (Framework, error) {
	f, ok := frameworks[j]
	if !ok {
		return Framework{}, fmt.Errorf("%w: %q", ErrUnknownJurisdiction, j)
	}
	return f, nil
}

// Jurisdictions returns the analysed jurisdictions, sorted.
func Jurisdictions() []Jurisdiction {
	out := make([]Jurisdiction, 0, len(frameworks))
	for j := range frameworks {
		out = append(out, j)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Organization is the legal profile of one customer.
type Organization struct {
	// ID identifies the organisation.
	ID string
	// Jurisdiction is where the customer is established. It is not the region the
	// platform runs in.
	Jurisdiction Jurisdiction
	// PlatformRegion is where the platform runs for this organisation. It is
	// recorded so that the difference between the two facts is explicit.
	PlatformRegion string
	// Acceptances are the documents the organisation accepted.
	Acceptances []Acceptance
	// Owners are the named duty owners.
	Owners []Owner
}

// Review is the outcome of a launch review.
type Review struct {
	// Organization is the organisation reviewed.
	Organization string
	// Framework is the framework that applied.
	Framework Framework
	// MissingArtifacts names the required documents that were not accepted.
	MissingArtifacts []ArtifactKind
	// StaleArtifacts names the documents whose accepted version is behind the
	// published one.
	StaleArtifacts []ArtifactKind
	// MissingDuties names the required duties with no owner.
	MissingDuties []Duty
	// Owners are the named owners, sorted by duty.
	Owners []Owner
	// Launchable reports whether every obligation is met.
	Launchable bool
}

// ReviewOrganization checks an organisation against its jurisdiction's framework.
//
// The three failures are reported together rather than one at a time, because a launch
// review that reports one problem at a time turns into a sequence of reviews, and each
// sequence is another chance for something to be missed.
func ReviewOrganization(org Organization, published []Artifact) (Review, error) {
	if strings.TrimSpace(string(org.Jurisdiction)) == "" {
		return Review{}, ErrNoJurisdiction
	}
	framework, err := FrameworkFor(org.Jurisdiction)
	if err != nil {
		return Review{}, err
	}
	review := Review{Organization: org.ID, Framework: framework}

	current := make(map[ArtifactKind]Artifact, len(published))
	for _, a := range published {
		current[a.Kind] = a
	}
	accepted := make(map[ArtifactKind]Acceptance, len(org.Acceptances))
	for _, a := range org.Acceptances {
		if strings.TrimSpace(a.Version) == "" {
			return Review{}, fmt.Errorf("%w: %q", ErrNoArtifactVersion, a.Kind)
		}
		accepted[a.Kind] = a
	}

	for _, kind := range framework.RequiredArtifacts {
		acc, ok := accepted[kind]
		if !ok {
			review.MissingArtifacts = append(review.MissingArtifacts, kind)
			continue
		}
		pub, published := current[kind]
		if !published {
			// The document is required but nothing publishes it, so there is no
			// version to be current. The acceptance cannot be shown to be
			// current either.
			review.StaleArtifacts = append(review.StaleArtifacts, kind)
			continue
		}
		if acc.Version != pub.Version {
			review.StaleArtifacts = append(review.StaleArtifacts, kind)
		}
	}

	owned := make(map[Duty]Owner, len(org.Owners))
	for _, o := range org.Owners {
		if strings.TrimSpace(o.Name) == "" {
			return Review{}, fmt.Errorf("%w: duty %q", ErrNoOwnerName, o.Duty)
		}
		owned[o.Duty] = o
	}
	for _, duty := range framework.RequiredDuties {
		if _, ok := owned[duty]; !ok {
			review.MissingDuties = append(review.MissingDuties, duty)
			continue
		}
		review.Owners = append(review.Owners, owned[duty])
	}

	sort.Slice(review.Owners, func(i, j int) bool { return review.Owners[i].Duty < review.Owners[j].Duty })
	sort.Slice(review.MissingArtifacts, func(i, j int) bool { return review.MissingArtifacts[i] < review.MissingArtifacts[j] })
	sort.Slice(review.StaleArtifacts, func(i, j int) bool { return review.StaleArtifacts[i] < review.StaleArtifacts[j] })
	sort.Slice(review.MissingDuties, func(i, j int) bool { return review.MissingDuties[i] < review.MissingDuties[j] })

	review.Launchable = len(review.MissingArtifacts) == 0 &&
		len(review.StaleArtifacts) == 0 &&
		len(review.MissingDuties) == 0
	return review, nil
}

// RightsRequestKind is the kind of rights request being made.
type RightsRequestKind string

const (
	// RightsAccess is a request to see the personal data held.
	RightsAccess RightsRequestKind = "access"
	// RightsErasure is a request to delete personal data.
	RightsErasure RightsRequestKind = "erasure"
	// RightsPortability is a request for data in a portable form.
	RightsPortability RightsRequestKind = "portability"
	// RightsCorrection is a request to correct personal data.
	RightsCorrection RightsRequestKind = "correction"
	// RightsObjection is a request to object to processing.
	RightsObjection RightsRequestKind = "objection"
)

// RightsRequest is a request to exercise a data subject right.
type RightsRequest struct {
	// Kind is the right being exercised.
	Kind RightsRequestKind
	// ReceivedAt is when the request arrived.
	ReceivedAt time.Time
	// Organization is the customer it belongs to.
	Organization string
}

// RightsDeadline returns the date a rights request must be answered by.
//
// The period comes from the framework, so an overdue request is detected by
// arithmetic rather than by somebody noticing. A deadline that lives in a document is
// a deadline that is met until the first busy week.
func RightsDeadline(j Jurisdiction, kind RightsRequestKind, receivedAt time.Time) (time.Time, error) {
	if strings.TrimSpace(string(kind)) == "" {
		return time.Time{}, ErrNoRequestKind
	}
	switch kind {
	case RightsAccess, RightsErasure, RightsPortability, RightsCorrection, RightsObjection:
	default:
		return time.Time{}, fmt.Errorf("%w: %q", ErrUnknownRequestKind, kind)
	}
	framework, err := FrameworkFor(j)
	if err != nil {
		return time.Time{}, err
	}
	return receivedAt.AddDate(0, 0, framework.RightsResponseDays), nil
}

// BreachDeadline returns the date a notifiable breach must be reported by.
//
// The period differs by framework and the arithmetic is derived rather than stored,
// so a change to a framework changes the deadline everywhere at once. A framework
// with no statutory period falls back to the baseline rather than to "no deadline",
// because "no deadline" is how an incident is reported on the day somebody remembers.
func BreachDeadline(j Jurisdiction, detectedAt time.Time) (time.Time, error) {
	if detectedAt.IsZero() {
		return time.Time{}, ErrNoDetectionTime
	}
	framework, err := FrameworkFor(j)
	if err != nil {
		return time.Time{}, err
	}
	hours := framework.BreachNotificationHours
	if hours == 0 {
		hours = frameworks[JurisdictionGlobal].BreachNotificationHours
	}
	return detectedAt.Add(time.Duration(hours) * time.Hour), nil
}

// Overdue reports whether a rights request has passed its deadline.
func Overdue(j Jurisdiction, req RightsRequest, at time.Time) (bool, error) {
	deadline, err := RightsDeadline(j, req.Kind, req.ReceivedAt)
	if err != nil {
		return false, err
	}
	return at.After(deadline), nil
}
