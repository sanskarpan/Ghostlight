// Package support implements the customer-facing support surfaces of checklist row
// G7.8: the requests a customer opens, the comments that record what was said about
// them, and the help articles a console screen links to.
//
// The sibling package internal/communications owns the severity vocabulary and the
// promises that go with it. This package does not define a second one. A support
// request is urgent or it is not urgent in exactly the way an incident is, and it
// carries the same commitment: a SEV1 request is answered inside the fifteen
// minutes we have already promised a SEV1 incident will be noticed inside. A
// second vocabulary would let a request be urgent by a rule nobody has written
// down, and the two surfaces would then answer the same question differently.
//
// The first property is that **the deadline is derived, never chosen**. A ticket
// system where the responder picks the due date is a ticket system where the
// commitment is negotiable, and a commitment that can be negotiated is not a
// commitment. So a request's due date must equal the moment it was received plus
// the customer-notice period its severity already commits us to, and a request
// whose due date says anything else is refused with both dates in the message. The
// severity comes from the communications package, which is what makes the two
// surfaces answer the same question the same way.
//
// The second property is that **the conversation is append-only**. Messages are
// inserted where their timestamp belongs, and nothing already recorded is removed
// or reordered, because a thread that can be edited is a thread that can be
// edited to look better than it was. A resolved request is closed: it takes no
// more messages and no more comments, and its record stops changing.
//
// The third property is that **being late is arithmetic, not a notice**. Nobody
// has to remember to say a request is overdue, because the due date and the
// moment decide it, every time, with no memory involved. A deadline that lives in
// a document is a deadline that is met until the first busy week.
//
// The fourth property is that **a request belongs to one organization**. A
// customer sees only their own requests, and a request belonging to another
// organization is not refused with a reason: it is absent, because a reason would
// confirm that it exists, and a confirmation is a leak.
//
// The fifth property is that **internal notes and guest-visible threads are
// separate** (docs/JOURNEYS.md). A comment is either internal or customer
// visible, and it says so, because a comment with an unset visibility would
// default to one of the two, and the wrong default leaks our notes to the
// customer. ForCustomer is the only way to get a list a customer may read, and a
// comment whose visibility nobody recognises is never in it.
//
// The sixth property is that **help is pinned and it exists**. An article carries
// a version, so a console can say which version of a page the customer is
// reading, and a screen that links to help must have help: a surface with no
// articles fails loudly when the link is built rather than when a customer
// clicks it. A reference to an article that does not exist is refused for the
// same reason. A dangling help link is a support ticket with extra steps.
package support

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/communications"
)

// Errors returned by this package's support rules.
var (
	// ErrNoRequestID means a support request carries no identifier. A request
	// nobody can name cannot be quoted back to the customer or found again
	// when they ask about it.
	ErrNoRequestID = errors.New("support request must carry an identifier")
	// ErrNoOrganization means a support request names no organization. A
	// request belonging to nobody belongs to whoever opens it.
	ErrNoOrganization = errors.New("support request must name an organization")
	// ErrNoSubject means a support request carries no subject. A request
	// without a headline is a message nobody can triage.
	ErrNoSubject = errors.New("support request must carry a subject")
	// ErrNoBody means a request, a message, a comment or an article carries
	// no body. Empty content is not a record of anything.
	ErrNoBody = errors.New("content must carry a body")
	// ErrNoReceivedAt means a support request carries no received time. A
	// request with no arrival has no deadline to be measured against, because
	// the deadline is derived from the arrival.
	ErrNoReceivedAt = errors.New("support request must carry a received time")
	// ErrUnknownSeverity means a request carries a severity this package does
	// not define. The severity is what commits us to a deadline, so an
	// undefined severity is a request with no commitment attached to it.
	ErrUnknownSeverity = errors.New("unknown severity")
	// ErrDueDateMismatch means a request's due date is not the date its
	// severity commits us to. The deadline is derived, so a due date that
	// says something else is a deadline somebody chose.
	ErrDueDateMismatch = errors.New("support request due date does not match the severity commitment")
	// ErrDueDateInPast means a request was due before it was received. A
	// deadline that has already passed was not met, it was missed at the
	// moment the request arrived.
	ErrDueDateInPast = errors.New("support request due date is in the past")
	// ErrNoAuthor means a message or a comment names no author. A note
	// nobody wrote cannot be asked about.
	ErrNoAuthor = errors.New("content must name an author")
	// ErrMessageBeforeRequest means a message is dated before the request
	// was received. It does not belong to this request.
	ErrMessageBeforeRequest = errors.New("message is dated before the request was received")
	// ErrRequestResolved means something was written on a request that is
	// already closed. A resolved request keeps its record and stops taking
	// new entries.
	ErrRequestResolved = errors.New("support request is already resolved")
	// ErrNoResolution means a resolution carries no note. "Resolved" with
	// nothing said about what happened is the least useful word in a support
	// record.
	ErrNoResolution = errors.New("support request resolution must carry a note")
	// ErrAlreadyResolved means a request was resolved twice. The record is
	// closed, and a second resolution would rewrite it.
	ErrAlreadyResolved = errors.New("support request is already resolved")
	// ErrNoCommentID means a comment carries no identifier. Comments are
	// referenced from the request's own history.
	ErrNoCommentID = errors.New("comment must carry an identifier")
	// ErrUnknownVisibility means a comment carries a visibility this package
	// does not define. A comment with an unset visibility would default to
	// one of the two, and the wrong default leaks internal notes to
	// customers.
	ErrUnknownVisibility = errors.New("unknown comment visibility")
	// ErrNoArticleID means a help article carries no identifier. Help links
	// name articles, and a link that names nothing dangles.
	ErrNoArticleID = errors.New("help article must carry an identifier")
	// ErrNoTitle means a help article carries no title. An article without a
	// headline cannot be listed on a screen.
	ErrNoTitle = errors.New("help article must carry a title")
	// ErrNoSurface means a help article names no surface. Help belongs to
	// the screen it explains, and an article that names no screen is
	// attached to all of them at once.
	ErrNoSurface = errors.New("help article must name a surface")
	// ErrNoVersion means a help article carries no version. An article with
	// no version cannot be pinned, and a pinned help link is what lets a
	// console say that the customer is reading the version that matches this
	// screen.
	ErrNoVersion = errors.New("help article must carry a version")
	// ErrNoPublishedAt means a help article was never published. An article
	// with no publication time is a draft, and a draft is not what a customer
	// is linked to.
	ErrNoPublishedAt = errors.New("help article must carry a publication time")
	// ErrDuplicateArticle means two help articles share an identifier, which
	// makes every reference to that identifier ambiguous.
	ErrDuplicateArticle = errors.New("help article identifier is already in use")
	// ErrNoSuchArticle means a help reference names an article that does not
	// exist. A dangling help link is a support ticket with extra steps, and
	// it should fail when the link is built rather than when a customer
	// clicks it.
	ErrNoSuchArticle = errors.New("no such help article")
	// ErrNoHelpForSurface means a surface has no help at all. A console
	// screen that links to help must have help, and a screen whose help was
	// renamed should fail loudly.
	ErrNoHelpForSurface = errors.New("no help for that surface")
	// ErrDuplicateRequest means two support requests share an identifier,
	// which makes every reference to that identifier ambiguous.
	ErrDuplicateRequest = errors.New("support request identifier is already in use")
)

// RequestStatus is where a support request stands.
type RequestStatus string

const (
	// RequestOpen means the request is live and nobody has answered it yet.
	RequestOpen RequestStatus = "open"
	// RequestPending means the request is waiting on the customer. It is
	// still live: the deadline does not stop running because the ball is in
	// somebody else's court.
	RequestPending RequestStatus = "pending"
	// RequestResolved means the request is closed and carries a resolution.
	RequestResolved RequestStatus = "resolved"
)

// Message is one entry in a request's conversation with the customer.
type Message struct {
	// At is when the message was sent.
	At time.Time
	// Author is who sent it.
	Author string
	// Body is what it says.
	Body string
}

// Request is a support request from a customer.
//
// The due date is a derived field, not a chosen one: it must equal the received
// time plus the customer-notice period the severity commits us to. Everything
// else about the request is what the customer told us.
type Request struct {
	// ID identifies the request.
	ID string
	// Organization names the organization the request belongs to. A request
	// belongs to exactly one.
	Organization string
	// Subject is the request's headline.
	Subject string
	// Body is what the customer said.
	Body string
	// Severity is how urgent the request is. It is one of the severities the
	// communications package defines, and it is what sets the deadline.
	Severity communications.Severity
	// Category is what the request is about, such as "preview" or "billing".
	// It is free text and it does not affect any rule here.
	Category string
	// ReceivedAt is when the request arrived.
	ReceivedAt time.Time
	// DueAt is when the request has to be answered by. It is derived from
	// the severity's customer-notice commitment and is refused if it says
	// anything else.
	DueAt time.Time
	// Status is where the request stands. An unset status is read as open,
	// because a request nobody has looked at yet is open.
	Status RequestStatus
	// ResolvedAt is when the request was resolved.
	ResolvedAt time.Time
	// Resolution says what resolved it.
	Resolution string
	// Messages is the conversation with the customer, oldest first. It is
	// append-only.
	Messages []Message
	// Comments are the notes written on the request, oldest first. Internal
	// notes and customer-visible notes live in the same list but are
	// separated by their visibility.
	Comments []Comment
}

// Validate refuses a request that could not be filed.
//
// The order of the checks is the policy. Identity comes first, because a
// request nobody can refer to is not usable at all. The severity comes next,
// because it decides the deadline and a deadline that is not derived from a
// severity is a deadline somebody chose. The due date comes last, because
// every earlier refusal is a fact about the request itself and this one is a
// fact about the promise attached to it.
//
// The due date is checked against the commitment in two steps, and the order
// matters. A due date before the request arrived is reported as a deadline in
// the past, because that is the more precise name for it. A due date that is
// after the arrival but is not the derived one is a mismatch, and the refusal
// names both dates, because the responder who set it has to see which deadline
// the severity actually commits us to.
func (r Request) Validate() error {
	if strings.TrimSpace(r.ID) == "" {
		return ErrNoRequestID
	}
	if strings.TrimSpace(r.Organization) == "" {
		return fmt.Errorf("%w: request %q", ErrNoOrganization, r.ID)
	}
	if strings.TrimSpace(r.Subject) == "" {
		return fmt.Errorf("%w: request %q", ErrNoSubject, r.ID)
	}
	if strings.TrimSpace(r.Body) == "" {
		return fmt.Errorf("%w: request %q", ErrNoBody, r.ID)
	}
	definition, err := communications.DefinitionFor(r.Severity)
	if err != nil {
		return unknownSeverity(r.Severity, err)
	}
	if r.ReceivedAt.IsZero() {
		return fmt.Errorf("%w: request %q", ErrNoReceivedAt, r.ID)
	}
	expected := r.ReceivedAt.Add(definition.CustomerNoticeWithin)
	switch {
	case r.DueAt.IsZero():
		return fmt.Errorf("%w: request %q has no due date; the %s commitment makes it due at %s",
			ErrDueDateMismatch, r.ID, r.Severity, stamp(expected))
	case r.DueAt.Before(r.ReceivedAt):
		return fmt.Errorf("%w: request %q is due at %s and was received at %s",
			ErrDueDateInPast, r.ID, stamp(r.DueAt), stamp(r.ReceivedAt))
	case !r.DueAt.Equal(expected):
		return fmt.Errorf("%w: request %q is due at %s but the %s commitment makes it due at %s",
			ErrDueDateMismatch, r.ID, stamp(r.DueAt), r.Severity, stamp(expected))
	}
	return nil
}

// DueAt returns the deadline a request received at the given moment carries.
//
// The deadline is derived from the severity's customer-notice commitment, which
// is the same commitment the communications package makes about notices. It is
// offered here so that a caller fills the field in rather than typing a date
// of its own: a ticket system where the responder picks the deadline is a
// ticket system where the commitment is negotiable.
func DueAt(receivedAt time.Time, severity communications.Severity) (time.Time, error) {
	definition, err := communications.DefinitionFor(severity)
	if err != nil {
		return time.Time{}, unknownSeverity(severity, err)
	}
	return receivedAt.Add(definition.CustomerNoticeWithin), nil
}

// unknownSeverity reports a severity the communications package does not define.
//
// The refusal matches this package's ErrUnknownSeverity and the communications
// package's own, because there is one severity vocabulary in the system and a
// caller checking either name has to be told the same thing.
func unknownSeverity(severity communications.Severity, cause error) error {
	return severityError{severity: severity, cause: cause}
}

// severityError is the refusal for a severity nobody defines.
type severityError struct {
	// severity is the severity that was refused.
	severity communications.Severity
	// cause is the communications package's own refusal.
	cause error
}

// Error names the severity that was refused.
func (e severityError) Error() string {
	return fmt.Sprintf("unknown severity %q", e.severity)
}

// Unwrap reaches the communications package's own refusal.
func (e severityError) Unwrap() error {
	return e.cause
}

// Is matches this package's severity refusal and the communications package's.
func (e severityError) Is(target error) bool {
	return target == ErrUnknownSeverity || target == communications.ErrUnknownSeverity
}

// AddMessage appends a message to a request's conversation.
//
// The conversation is append-only. The message is inserted where its timestamp
// belongs, so the thread stays in order without anything already recorded
// being removed or reordered, and refusing an out-of-order message instead
// would lose a message that really happened.
//
// The order of the refusals is the policy. What the author wrote is checked
// first, because a message with no body says nothing and a message nobody
// wrote cannot be asked about, and a message dated before the request arrived
// does not belong to this request. The state of the request is checked last,
// because a request that is already resolved takes no more messages at all.
func AddMessage(r Request, m Message) (Request, error) {
	if strings.TrimSpace(m.Body) == "" {
		return r, fmt.Errorf("%w: message on request %q", ErrNoBody, r.ID)
	}
	if strings.TrimSpace(m.Author) == "" {
		return r, fmt.Errorf("%w: message on request %q", ErrNoAuthor, r.ID)
	}
	if !r.ReceivedAt.IsZero() && m.At.Before(r.ReceivedAt) {
		return r, fmt.Errorf("%w: message on request %q received at %s is dated %s",
			ErrMessageBeforeRequest, r.ID, stamp(r.ReceivedAt), stamp(m.At))
	}
	if r.Status == RequestResolved {
		return r, fmt.Errorf("%w: request %q", ErrRequestResolved, r.ID)
	}
	out := r
	out.Messages = insertMessage(r.Messages, m)
	return out, nil
}

// insertMessage puts a message where its timestamp belongs.
//
// A message with the same timestamp as one already recorded goes after it, so
// two messages written in the same moment keep the order they were written in.
func insertMessage(messages []Message, m Message) []Message {
	out := make([]Message, 0, len(messages)+1)
	placed := false
	for _, existing := range messages {
		if !placed && existing.At.After(m.At) {
			out = append(out, m)
			placed = true
		}
		out = append(out, existing)
	}
	if !placed {
		out = append(out, m)
	}
	return out
}

// Resolve closes a request.
//
// A resolution carries a note, because "resolved" on its own is the least
// useful word in a support record: it says the request stopped and nothing
// about what happened. A request that is already resolved is not resolved
// again, because its record is closed and a second resolution would rewrite
// it.
func Resolve(r Request, note string, at time.Time) (Request, error) {
	if strings.TrimSpace(note) == "" {
		return r, fmt.Errorf("%w: request %q", ErrNoResolution, r.ID)
	}
	if r.Status == RequestResolved {
		return r, fmt.Errorf("%w: request %q", ErrAlreadyResolved, r.ID)
	}
	out := r
	out.Status = RequestResolved
	out.ResolvedAt = at
	out.Resolution = strings.TrimSpace(note)
	return out, nil
}

// Overdue reports whether a request is past its deadline and still live.
//
// Being late is arithmetic, not something anybody has to notice. The deadline
// and the moment decide it, every time, with no memory involved, because a
// deadline that lives in a document is a deadline that is met until the first
// busy week.
//
// A resolved request is never overdue: the work is finished, however long it
// took. A request with no deadline at all is overdue, because it is late
// against every deadline it ought to have had.
func Overdue(r Request, at time.Time) bool {
	if r.Status == RequestResolved {
		return false
	}
	return at.After(r.DueAt)
}

// VisibleTo returns the requests an organization is allowed to see.
//
// A request belonging to another organization is not in the list at all, which
// is the same answer the organization would have got if the request had never
// been written. A refusal would confirm that it exists, and a confirmation is a
// leak. An organization that names nobody is matched by nothing, because the
// empty string is not an organization.
func VisibleTo(requests []Request, organization string) []Request {
	org := strings.TrimSpace(organization)
	if org == "" {
		return nil
	}
	var out []Request
	for _, r := range requests {
		if strings.TrimSpace(r.Organization) != org {
			continue
		}
		out = append(out, r)
	}
	return out
}

// Visibility says who a comment may be read by.
type Visibility string

const (
	// CommentInternal is a note that is ours. The customer never reads it.
	CommentInternal Visibility = "internal"
	// CommentCustomerVisible is a note the customer is allowed to read.
	CommentCustomerVisible Visibility = "customer-visible"
)

// Actor is whoever is looking at a comment.
type Actor struct {
	// Internal reports whether the actor works on our side of the boundary
	// between our notes and the customer's.
	Internal bool
}

// Comment is one note written on a request.
//
// The visibility is a required field rather than a default, because the two
// possible defaults are opposite and one of them leaks. A comment that says
// nothing about who may read it has to be refused rather than guessed at.
type Comment struct {
	// ID identifies the comment.
	ID string
	// Author is who wrote it.
	Author string
	// Body is what it says.
	Body string
	// At is when it was written.
	At time.Time
	// Visibility says who may read it. It is one of the two this package
	// defines, and it is never left unset.
	Visibility Visibility
}

// Validate refuses a comment that could not be written.
//
// The visibility is checked last, because the fields before it describe a
// comment that exists and the visibility says whether that comment may be read
// by the customer. An unrecognised visibility is not treated as internal: the
// check fails closed, so a comment nobody can classify is one a customer
// cannot see.
func (c Comment) Validate() error {
	if strings.TrimSpace(c.ID) == "" {
		return ErrNoCommentID
	}
	if strings.TrimSpace(c.Author) == "" {
		return fmt.Errorf("%w: comment %q", ErrNoAuthor, c.ID)
	}
	if strings.TrimSpace(c.Body) == "" {
		return fmt.Errorf("%w: comment %q", ErrNoBody, c.ID)
	}
	switch c.Visibility {
	case CommentInternal, CommentCustomerVisible:
	default:
		return fmt.Errorf("%w: comment %q carries %q", ErrUnknownVisibility, c.ID, c.Visibility)
	}
	return nil
}

// VisibleTo reports whether an actor may read this comment.
//
// An internal actor sees everything, because our own notes are ours. A
// customer sees only the comments that were marked customer-visible, and a
// comment whose visibility nobody recognises is not one of those: the check
// fails closed, because a note that was never classified must not be read by
// somebody who was not meant to read it.
func (c Comment) VisibleTo(actor Actor) bool {
	if actor.Internal {
		return true
	}
	return c.Visibility == CommentCustomerVisible
}

// ForCustomer returns the comments a customer may read.
//
// This is the only way to get a list a customer is shown, so a caller cannot
// forget to apply it and hand over our internal notes. A comment that is
// internal, or whose visibility nobody recognises, is not in the list.
func ForCustomer(comments []Comment) []Comment {
	var out []Comment
	for _, c := range comments {
		if c.Visibility != CommentCustomerVisible {
			continue
		}
		out = append(out, c)
	}
	return out
}

// AddComment writes a note on a request.
//
// The comment is checked before the request, because a comment that could not
// be written is a worse mistake than one written too late, and the request's
// state is checked last: a resolved request takes no more comments, exactly as
// it takes no more messages.
func AddComment(r Request, c Comment) (Request, error) {
	if err := c.Validate(); err != nil {
		return r, err
	}
	if r.Status == RequestResolved {
		return r, fmt.Errorf("%w: request %q", ErrRequestResolved, r.ID)
	}
	out := r
	out.Comments = insertComment(r.Comments, c)
	return out, nil
}

// insertComment puts a comment where its timestamp belongs.
//
// A comment with the same timestamp as one already recorded goes after it, so
// two notes written in the same moment keep the order they were written in.
func insertComment(comments []Comment, c Comment) []Comment {
	out := make([]Comment, 0, len(comments)+1)
	placed := false
	for _, existing := range comments {
		if !placed && existing.At.After(c.At) {
			out = append(out, c)
			placed = true
		}
		out = append(out, existing)
	}
	if !placed {
		out = append(out, c)
	}
	return out
}

// Article is a help article a console screen links to.
//
// The version is what makes the article a document rather than a page: it is
// what a console cites when it says that the customer is reading the version
// that matches this screen.
type Article struct {
	// ID identifies the article, and it is what a help reference names.
	ID string
	// Title is the article's headline.
	Title string
	// Body is the article's text.
	Body string
	// Surface names the screen the article explains, such as "queue".
	Surface string
	// Version is the version of the article.
	Version string
	// PublishedAt is when the article was published.
	PublishedAt time.Time
}

// Validate refuses an article that could not be published.
//
// The order of the checks is the policy. Identity comes first, because an
// article nobody can link to is not usable. The title and the body come next,
// because an article with no headline cannot be listed and an article with no
// text says nothing. The surface comes after them, because the surface is what
// decides which screen the article appears on, and the version comes after that
// because an article with no version cannot be pinned. The publication time
// comes last, because it is the one field that only exists once the article is
// ready.
func (a Article) Validate() error {
	if strings.TrimSpace(a.ID) == "" {
		return ErrNoArticleID
	}
	if strings.TrimSpace(a.Title) == "" {
		return fmt.Errorf("%w: article %q", ErrNoTitle, a.ID)
	}
	if strings.TrimSpace(a.Body) == "" {
		return fmt.Errorf("%w: article %q", ErrNoBody, a.ID)
	}
	if strings.TrimSpace(a.Surface) == "" {
		return fmt.Errorf("%w: article %q", ErrNoSurface, a.ID)
	}
	if strings.TrimSpace(a.Version) == "" {
		return fmt.Errorf("%w: article %q", ErrNoVersion, a.ID)
	}
	if a.PublishedAt.IsZero() {
		return fmt.Errorf("%w: article %q", ErrNoPublishedAt, a.ID)
	}
	return nil
}

// ValidateArticles refuses a set of articles that could not be published.
//
// The duplicate check is part of it, because a set with two articles under one
// identifier makes every reference to that identifier ambiguous, and no
// per-article rule can see it.
func ValidateArticles(articles []Article) error {
	seen := map[string]bool{}
	for _, a := range articles {
		if err := a.Validate(); err != nil {
			return err
		}
		if seen[a.ID] {
			return fmt.Errorf("%w: %q", ErrDuplicateArticle, a.ID)
		}
		seen[a.ID] = true
	}
	return nil
}

// HelpFor returns the help articles for a surface.
//
// A surface with no articles is refused rather than answered with an empty
// list, because a console screen that links to help must have help, and a
// screen whose help was renamed should fail loudly when the link is built
// rather than when a customer clicks it.
//
// The result is sorted by article identifier and is deterministic, so the same
// set of articles always produces the same list whatever order they arrived
// in.
func HelpFor(surface string, articles []Article) ([]Article, error) {
	name := strings.TrimSpace(surface)
	if name == "" {
		return nil, fmt.Errorf("%w: no surface named", ErrNoHelpForSurface)
	}
	var out []Article
	for _, a := range articles {
		if strings.TrimSpace(a.Surface) != name {
			continue
		}
		out = append(out, a)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: surface %q", ErrNoHelpForSurface, surface)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// ResolveHelp returns the article a help reference names.
//
// A reference to an article that does not exist is refused rather than answered
// with an empty article, because a dangling help link is a support ticket with
// extra steps, and it should fail when the link is built rather than when a
// customer clicks it.
func ResolveHelp(reference string, articles []Article) (Article, error) {
	id := strings.TrimSpace(reference)
	if id == "" {
		return Article{}, fmt.Errorf("%w: %q", ErrNoSuchArticle, reference)
	}
	for _, a := range articles {
		if a.ID == id {
			return a, nil
		}
	}
	return Article{}, fmt.Errorf("%w: %q", ErrNoSuchArticle, reference)
}

// Registry is the set of support requests and help articles.
//
// The registry is where the support surfaces actually live, so it is where the
// duplicates are refused: two requests with one identifier make every
// reference to that identifier ambiguous, and two articles under one identifier
// make every help link ambiguous.
type Registry struct {
	// Requests are the support requests.
	Requests []Request
	// Articles are the help articles.
	Articles []Article
}

// AddRequest records a request.
//
// The duplicate check comes first: a request that reuses an identifier is
// refused before its contents are considered, because an ambiguous identifier
// is a problem whatever the request says.
func (r Registry) AddRequest(req Request) (Registry, error) {
	for _, existing := range r.Requests {
		if existing.ID == req.ID {
			return r, fmt.Errorf("%w: %q", ErrDuplicateRequest, req.ID)
		}
	}
	if err := req.Validate(); err != nil {
		return r, err
	}
	out := r
	out.Requests = append(append([]Request{}, r.Requests...), req)
	return out, nil
}

// AddArticle records a help article.
//
// The duplicate check comes first, for the same reason as on a request: an
// ambiguous identifier is a problem whatever the article says.
func (r Registry) AddArticle(a Article) (Registry, error) {
	for _, existing := range r.Articles {
		if existing.ID == a.ID {
			return r, fmt.Errorf("%w: %q", ErrDuplicateArticle, a.ID)
		}
	}
	if err := a.Validate(); err != nil {
		return r, err
	}
	out := r
	out.Articles = append(append([]Article{}, r.Articles...), a)
	return out, nil
}

// OverdueRequests returns the requests that are past their deadline.
//
// The list is sorted by request identifier and is deterministic. Nothing has
// to remember to file a request as overdue: the deadline and the moment decide
// it, every time.
func (r Registry) OverdueRequests(at time.Time) []Request {
	var out []Request
	for _, req := range r.Requests {
		if !Overdue(req, at) {
			continue
		}
		out = append(out, req)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// stamp renders a moment the way refusals name it.
//
// The moments are always rendered in UTC so that a refusal reads the same in
// every timezone, and so that two refusals about the same moment look alike.
func stamp(at time.Time) string {
	return at.UTC().Format(time.RFC3339)
}
