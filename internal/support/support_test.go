package support

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/communications"
)

// now is the moment every test in this file is written around.
var now = time.Date(2027, 1, 12, 10, 0, 0, 0, time.UTC)

// noticeWindow is the customer-notice period the communications package commits
// to for a severity.
func noticeWindow(severity communications.Severity) time.Duration {
	definition, err := communications.DefinitionFor(severity)
	if err != nil {
		panic(err)
	}
	return definition.CustomerNoticeWithin
}

// validRequest is a request that satisfies every rule, used as the base that
// each test breaks in one place.
func validRequest() Request {
	return Request{
		ID:           "req-1",
		Organization: "acme",
		Subject:      "Preview never becomes ready",
		Body:         "The build finished but the preview stays queued.",
		Severity:     communications.Sev3,
		Category:     "preview",
		ReceivedAt:   now,
		DueAt:        now.Add(noticeWindow(communications.Sev3)),
		Status:       RequestOpen,
	}
}

// validComment is a comment that satisfies every rule.
func validComment() Comment {
	return Comment{
		ID:         "c-1",
		Author:     "ada",
		Body:       "The queue is waiting on a capacity grant.",
		At:         now.Add(time.Hour),
		Visibility: CommentInternal,
	}
}

// validArticle is a help article that satisfies every rule.
func validArticle() Article {
	return Article{
		ID:          "help-1",
		Title:       "Why a preview is queued",
		Body:        "A preview waits until its capacity grant is approved.",
		Surface:     "queue",
		Version:     "2",
		PublishedAt: now,
	}
}

// ---------------------------------------------------------------------------
// Support requests
// ---------------------------------------------------------------------------

// A request that could not be filed is refused, and the refusal names what was
// missing.
func TestRequestValidateRefusesRequestsThatCannotBeFiled(t *testing.T) {
	cases := map[string]struct {
		mutate func(*Request)
		want   error
	}{
		"no identifier":        {func(r *Request) { r.ID = "  " }, ErrNoRequestID},
		"no organization":      {func(r *Request) { r.Organization = "" }, ErrNoOrganization},
		"no subject":           {func(r *Request) { r.Subject = "" }, ErrNoSubject},
		"no body":              {func(r *Request) { r.Body = "" }, ErrNoBody},
		"unknown severity":     {func(r *Request) { r.Severity = "sev9" }, ErrUnknownSeverity},
		"no severity":          {func(r *Request) { r.Severity = "" }, ErrUnknownSeverity},
		"never received":       {func(r *Request) { r.ReceivedAt = time.Time{} }, ErrNoReceivedAt},
		"no due date":          {func(r *Request) { r.DueAt = time.Time{} }, ErrDueDateMismatch},
		"due date in the past": {func(r *Request) { r.DueAt = now.Add(-time.Hour) }, ErrDueDateInPast},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			r := validRequest()
			tc.mutate(&r)
			if err := r.Validate(); !errors.Is(err, tc.want) {
				t.Errorf("Validate error = %v, want %v", err, tc.want)
			}
		})
	}
}

// A valid request is accepted, so the refusals above are refusals of real gaps
// rather than of everything.
func TestValidRequestIsAccepted(t *testing.T) {
	if err := validRequest().Validate(); err != nil {
		t.Fatalf("Validate error = %v, want nil", err)
	}
}

// The severity vocabulary is the communications package's, so a request that
// carries a severity we define is accepted and one we do not define is refused
// under both names.
func TestSeverityVocabularyIsTheCommunicationsPackages(t *testing.T) {
	for _, severity := range communications.Severities() {
		r := validRequest()
		r.Severity = severity
		r.DueAt = now.Add(noticeWindow(severity))
		if err := r.Validate(); err != nil {
			t.Errorf("Validate error = %v for %s, want nil", err, severity)
		}
	}
	r := validRequest()
	r.Severity = "sev9"
	err := r.Validate()
	if !errors.Is(err, ErrUnknownSeverity) {
		t.Errorf("Validate error = %v, want ErrUnknownSeverity", err)
	}
	if !errors.Is(err, communications.ErrUnknownSeverity) {
		t.Errorf("Validate error = %v, want the communications package's ErrUnknownSeverity", err)
	}
}

// The deadline is derived from the severity's customer-notice commitment, not
// chosen by whoever opened the ticket.
func TestDueDateIsDerivedFromTheSeverityCommitment(t *testing.T) {
	for _, severity := range communications.Severities() {
		r := validRequest()
		r.Severity = severity
		r.DueAt = now.Add(noticeWindow(severity))
		if err := r.Validate(); err != nil {
			t.Errorf("Validate error = %v for %s, want nil", err, severity)
		}
		due, err := DueAt(now, severity)
		if err != nil {
			t.Fatalf("DueAt error = %v", err)
		}
		if !due.Equal(r.DueAt) {
			t.Errorf("DueAt = %s, want %s", stamp(due), stamp(r.DueAt))
		}
	}
}

// A ticket system where the responder picks the deadline is a ticket system
// where the commitment is negotiable, so a due date that is not the derived one
// is refused, and the refusal names both dates so the responder can see which
// deadline the severity actually commits us to.
func TestDueDateMismatchIsRefusedAndNamesBothDates(t *testing.T) {
	r := validRequest()
	r.DueAt = now.Add(72 * time.Hour)
	err := r.Validate()
	if !errors.Is(err, ErrDueDateMismatch) {
		t.Fatalf("Validate error = %v, want ErrDueDateMismatch", err)
	}
	derived := now.Add(noticeWindow(communications.Sev3))
	if !strings.Contains(err.Error(), stamp(r.DueAt)) {
		t.Errorf("the refusal must name the due date that was set, got %v", err)
	}
	if !strings.Contains(err.Error(), stamp(derived)) {
		t.Errorf("the refusal must name the derived deadline, got %v", err)
	}
}

// A deadline that has already passed was missed at the moment the request
// arrived, and it is reported as such rather than as a mismatch.
func TestDueDateInThePastIsRefused(t *testing.T) {
	r := validRequest()
	r.DueAt = now.Add(-time.Minute)
	err := r.Validate()
	if !errors.Is(err, ErrDueDateInPast) {
		t.Fatalf("Validate error = %v, want ErrDueDateInPast", err)
	}
	if !strings.Contains(err.Error(), stamp(r.DueAt)) {
		t.Errorf("the refusal must name the due date, got %v", err)
	}
}

// A request with no received time has no deadline to be measured against.
func TestRequestWithoutAReceivedTimeIsRefused(t *testing.T) {
	r := validRequest()
	r.ReceivedAt = time.Time{}
	err := r.Validate()
	if !errors.Is(err, ErrNoReceivedAt) {
		t.Fatalf("Validate error = %v, want ErrNoReceivedAt", err)
	}
}

// A message that says nothing, comes from nobody or belongs to another request
// is refused.
func TestAddMessageRefusesUnusableMessages(t *testing.T) {
	cases := map[string]struct {
		mutate func(*Message)
		want   error
	}{
		"no body":                  {func(m *Message) { m.Body = "  " }, ErrNoBody},
		"no author":                {func(m *Message) { m.Author = "" }, ErrNoAuthor},
		"dated before the request": {func(m *Message) { m.At = now.Add(-time.Second) }, ErrMessageBeforeRequest},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			r := validRequest()
			m := Message{At: now.Add(time.Hour), Author: "ada", Body: "we are looking at it"}
			tc.mutate(&m)
			if _, err := AddMessage(r, m); !errors.Is(err, tc.want) {
				t.Errorf("AddMessage error = %v, want %v", err, tc.want)
			}
		})
	}
}

// The conversation is append-only: a message that arrives late is inserted
// where its timestamp belongs and nothing already recorded is removed.
func TestMessagesAreAppendOnlyAndInTimeOrder(t *testing.T) {
	r := validRequest()
	late, err := AddMessage(r, Message{At: now.Add(2 * time.Hour), Author: "ada", Body: "second"})
	if err != nil {
		t.Fatalf("AddMessage: %v", err)
	}
	early, err := AddMessage(late, Message{At: now.Add(time.Hour), Author: "ada", Body: "first"})
	if err != nil {
		t.Fatalf("AddMessage: %v", err)
	}
	if len(early.Messages) != 2 {
		t.Fatalf("the conversation holds %d messages, want 2", len(early.Messages))
	}
	if early.Messages[0].Body != "first" || early.Messages[1].Body != "second" {
		t.Errorf("the conversation is not in time order: %+v", early.Messages)
	}
}

// A request that is already resolved takes no more messages.
func TestMessageOnAResolvedRequestIsRefused(t *testing.T) {
	r, err := Resolve(validRequest(), "the preview agent was restarted", now.Add(time.Hour))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	_, err = AddMessage(r, Message{At: now.Add(2 * time.Hour), Author: "ada", Body: "one more thing"})
	if !errors.Is(err, ErrRequestResolved) {
		t.Fatalf("AddMessage error = %v, want ErrRequestResolved", err)
	}
}

// "Resolved" with nothing said about what happened is the least useful word in
// a support record.
func TestResolveRequiresANote(t *testing.T) {
	_, err := Resolve(validRequest(), "   ", now.Add(time.Hour))
	if !errors.Is(err, ErrNoResolution) {
		t.Fatalf("Resolve error = %v, want ErrNoResolution", err)
	}
}

// A resolved request keeps its record and stops taking a second resolution.
func TestRequestResolvedTwiceIsRefused(t *testing.T) {
	r, err := Resolve(validRequest(), "the preview agent was restarted", now.Add(time.Hour))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if r.Status != RequestResolved {
		t.Errorf("Status = %q, want %q", r.Status, RequestResolved)
	}
	if !r.ResolvedAt.Equal(now.Add(time.Hour)) {
		t.Errorf("ResolvedAt = %s, want %s", stamp(r.ResolvedAt), stamp(now.Add(time.Hour)))
	}
	if r.Resolution != "the preview agent was restarted" {
		t.Errorf("Resolution = %q, want the note", r.Resolution)
	}
	_, err = Resolve(r, "another note", now.Add(2*time.Hour))
	if !errors.Is(err, ErrAlreadyResolved) {
		t.Fatalf("Resolve error = %v, want ErrAlreadyResolved", err)
	}
}

// Being late is arithmetic, not something anybody has to notice.
func TestOverdueIsArithmetic(t *testing.T) {
	r := validRequest()
	if Overdue(r, now) {
		t.Error("a request that has just arrived is not overdue")
	}
	if Overdue(r, r.DueAt) {
		t.Error("a request at its deadline has not passed it yet")
	}
	if !Overdue(r, r.DueAt.Add(time.Second)) {
		t.Error("a request past its deadline is overdue")
	}
	resolved, err := Resolve(r, "the preview agent was restarted", r.DueAt.Add(time.Minute))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if Overdue(resolved, r.DueAt.Add(time.Hour)) {
		t.Error("a resolved request is never overdue")
	}
}

// A request belongs to one organization, and another organization's request is
// absent rather than refused.
func TestVisibleToReturnsOnlyTheCallingOrganizationsRequests(t *testing.T) {
	acme := validRequest()
	other := validRequest()
	other.ID = "req-2"
	other.Organization = "globex"
	requests := []Request{acme, other}

	got := VisibleTo(requests, "acme")
	if len(got) != 1 {
		t.Fatalf("VisibleTo returned %d requests, want 1", len(got))
	}
	if got[0].ID != "req-1" {
		t.Errorf("VisibleTo returned request %q, want req-1", got[0].ID)
	}
	if got := VisibleTo(requests, "globex"); len(got) != 1 || got[0].ID != "req-2" {
		t.Errorf("VisibleTo for globex = %+v, want req-2", got)
	}
}

// A request belonging to another organization has to be indistinguishable from
// a request that was never written.
func TestAnotherOrganizationsRequestIsIndistinguishableFromAbsence(t *testing.T) {
	acme := validRequest()
	other := validRequest()
	other.ID = "req-2"
	other.Organization = "globex"
	requests := []Request{acme, other}

	// Acme must not be able to tell that a request belonging to somebody else
	// exists: the answer it gets is the answer it gets for a request that was
	// never written.
	outside := VisibleTo(requests, "acme")
	absent := VisibleTo([]Request{acme}, "acme")
	if len(outside) != len(absent) {
		t.Errorf("VisibleTo for an outsider returned %d requests, want %d", len(outside), len(absent))
	}
	if len(VisibleTo(requests, "nobody")) != 0 {
		t.Error("a request must not be visible to an organization that does not exist here")
	}
	if len(VisibleTo(requests, "")) != 0 {
		t.Error("a request must not be visible to an empty organization")
	}
}

// ---------------------------------------------------------------------------
// Comments
// ---------------------------------------------------------------------------

// A comment that could not be written is refused, and an unrecognised
// visibility is refused rather than guessed at.
func TestCommentValidateRefusesUnusableComments(t *testing.T) {
	cases := map[string]struct {
		mutate func(*Comment)
		want   error
	}{
		"no identifier":      {func(c *Comment) { c.ID = "" }, ErrNoCommentID},
		"no author":          {func(c *Comment) { c.Author = "" }, ErrNoAuthor},
		"no body":            {func(c *Comment) { c.Body = "" }, ErrNoBody},
		"no visibility":      {func(c *Comment) { c.Visibility = "" }, ErrUnknownVisibility},
		"unknown visibility": {func(c *Comment) { c.Visibility = "guest-visible" }, ErrUnknownVisibility},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c := validComment()
			tc.mutate(&c)
			if err := c.Validate(); !errors.Is(err, tc.want) {
				t.Errorf("Validate error = %v, want %v", err, tc.want)
			}
		})
	}
}

// A comment with an unset visibility would default to one of the two, and the
// wrong default leaks our notes, so it is refused at construction.
func TestCommentWithUnknownVisibilityIsRefusedAtConstruction(t *testing.T) {
	c := validComment()
	c.Visibility = ""
	if err := c.Validate(); !errors.Is(err, ErrUnknownVisibility) {
		t.Fatalf("Validate error = %v, want ErrUnknownVisibility", err)
	}
	if _, err := AddComment(validRequest(), c); !errors.Is(err, ErrUnknownVisibility) {
		t.Fatalf("AddComment error = %v, want ErrUnknownVisibility", err)
	}
}

// An internal note must never reach a customer.
func TestForCustomerExcludesInternalNotes(t *testing.T) {
	internal := validComment()
	visible := validComment()
	visible.ID = "c-2"
	visible.Visibility = CommentCustomerVisible
	unclassified := validComment()
	unclassified.ID = "c-3"
	unclassified.Visibility = "who knows"

	got := ForCustomer([]Comment{internal, visible, unclassified})
	if len(got) != 1 {
		t.Fatalf("ForCustomer returned %d comments, want 1", len(got))
	}
	if got[0].ID != "c-2" {
		t.Errorf("ForCustomer returned comment %q, want c-2", got[0].ID)
	}
}

// An internal actor sees everything; a customer sees only what was marked
// customer-visible.
func TestCommentVisibleToAnActor(t *testing.T) {
	internal := validComment()
	visible := validComment()
	visible.ID = "c-2"
	visible.Visibility = CommentCustomerVisible
	unclassified := validComment()
	unclassified.ID = "c-3"
	unclassified.Visibility = ""

	if !internal.VisibleTo(Actor{Internal: true}) {
		t.Error("an internal actor must see an internal note")
	}
	if !unclassified.VisibleTo(Actor{Internal: true}) {
		t.Error("an internal actor must see every note")
	}
	if internal.VisibleTo(Actor{}) {
		t.Error("a customer must not see an internal note")
	}
	if !visible.VisibleTo(Actor{}) {
		t.Error("a customer must see a customer-visible note")
	}
	if unclassified.VisibleTo(Actor{}) {
		t.Error("a comment nobody classified must not be visible to a customer")
	}
}

// A resolved request takes no more comments, exactly as it takes no more
// messages.
func TestCommentOnAResolvedRequestIsRefused(t *testing.T) {
	r, err := Resolve(validRequest(), "the preview agent was restarted", now.Add(time.Hour))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if _, err := AddComment(r, validComment()); !errors.Is(err, ErrRequestResolved) {
		t.Fatalf("AddComment error = %v, want ErrRequestResolved", err)
	}
}

// A comment is written on the request and inserted where its timestamp
// belongs.
func TestAddCommentAppendsInTimeOrder(t *testing.T) {
	r := validRequest()
	late := validComment()
	late.At = now.Add(2 * time.Hour)
	withLate, err := AddComment(r, late)
	if err != nil {
		t.Fatalf("AddComment: %v", err)
	}
	early := validComment()
	early.ID = "c-2"
	early.At = now.Add(time.Hour)
	withBoth, err := AddComment(withLate, early)
	if err != nil {
		t.Fatalf("AddComment: %v", err)
	}
	if len(withBoth.Comments) != 2 {
		t.Fatalf("the request holds %d comments, want 2", len(withBoth.Comments))
	}
	if withBoth.Comments[0].ID != "c-2" || withBoth.Comments[1].ID != "c-1" {
		t.Errorf("the comments are not in time order: %+v", withBoth.Comments)
	}
}

// Internal notes and guest-visible threads are separate: a message is the
// conversation with the customer and a comment is a note on the request, and
// the customer's view of a request carries only the customer-visible notes.
func TestInternalNotesAndCustomerThreadsAreSeparate(t *testing.T) {
	r := validRequest()
	r, err := AddMessage(r, Message{At: now.Add(time.Hour), Author: "ada", Body: "we are looking at it"})
	if err != nil {
		t.Fatalf("AddMessage: %v", err)
	}
	r, err = AddComment(r, validComment())
	if err != nil {
		t.Fatalf("AddComment: %v", err)
	}
	if len(r.Messages) != 1 {
		t.Errorf("the request holds %d messages, want 1", len(r.Messages))
	}
	if len(r.Comments) != 1 {
		t.Errorf("the request holds %d comments, want 1", len(r.Comments))
	}
	if len(ForCustomer(r.Comments)) != 0 {
		t.Error("an internal note must not be in the customer's list")
	}
}

// ---------------------------------------------------------------------------
// Help articles
// ---------------------------------------------------------------------------

// An article that could not be published is refused, and the refusal names
// what was missing.
func TestValidateArticlesRefusesUnusableArticles(t *testing.T) {
	cases := map[string]struct {
		mutate func(*Article)
		want   error
	}{
		"no identifier":   {func(a *Article) { a.ID = "" }, ErrNoArticleID},
		"no title":        {func(a *Article) { a.Title = "" }, ErrNoTitle},
		"no body":         {func(a *Article) { a.Body = "" }, ErrNoBody},
		"no surface":      {func(a *Article) { a.Surface = "" }, ErrNoSurface},
		"no version":      {func(a *Article) { a.Version = "" }, ErrNoVersion},
		"never published": {func(a *Article) { a.PublishedAt = time.Time{} }, ErrNoPublishedAt},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			a := validArticle()
			tc.mutate(&a)
			if err := ValidateArticles([]Article{a}); !errors.Is(err, tc.want) {
				t.Errorf("ValidateArticles error = %v, want %v", err, tc.want)
			}
		})
	}
}

// A valid set of articles is accepted, so the refusals above are refusals of
// real gaps rather than of everything.
func TestValidArticlesAreAccepted(t *testing.T) {
	second := validArticle()
	second.ID = "help-2"
	if err := ValidateArticles([]Article{validArticle(), second}); err != nil {
		t.Fatalf("ValidateArticles error = %v, want nil", err)
	}
}

// Two articles under one identifier make every help link ambiguous.
func TestValidateArticlesRefusesDuplicateIdentifiers(t *testing.T) {
	second := validArticle()
	if err := ValidateArticles([]Article{validArticle(), second}); !errors.Is(err, ErrDuplicateArticle) {
		t.Fatalf("ValidateArticles error = %v, want ErrDuplicateArticle", err)
	}
}

// A console screen that links to help must have help.
func TestHelpForReturnsTheArticlesForASurface(t *testing.T) {
	queue := validArticle()
	billing := validArticle()
	billing.ID = "help-2"
	billing.Surface = "billing"

	got, err := HelpFor("queue", []Article{billing, queue})
	if err != nil {
		t.Fatalf("HelpFor error = %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("HelpFor returned %d articles, want 1", len(got))
	}
	if got[0].ID != "help-1" {
		t.Errorf("HelpFor returned article %q, want help-1", got[0].ID)
	}
}

// A screen whose help was renamed should fail loudly rather than link to
// nothing.
func TestHelpForRefusesASurfaceWithNoHelp(t *testing.T) {
	if _, err := HelpFor("billing", []Article{validArticle()}); !errors.Is(err, ErrNoHelpForSurface) {
		t.Fatalf("HelpFor error = %v, want ErrNoHelpForSurface", err)
	}
	if _, err := HelpFor("", []Article{validArticle()}); !errors.Is(err, ErrNoHelpForSurface) {
		t.Fatalf("HelpFor error = %v, want ErrNoHelpForSurface", err)
	}
}

// A dangling help link is a support ticket with extra steps, and it should
// fail when the link is built rather than when a customer clicks it.
func TestResolveHelpRefusesADanglingReference(t *testing.T) {
	articles := []Article{validArticle()}
	if _, err := ResolveHelp("help-404", articles); !errors.Is(err, ErrNoSuchArticle) {
		t.Fatalf("ResolveHelp error = %v, want ErrNoSuchArticle", err)
	}
	if _, err := ResolveHelp("", articles); !errors.Is(err, ErrNoSuchArticle) {
		t.Fatalf("ResolveHelp error = %v, want ErrNoSuchArticle", err)
	}
}

// A reference that names an article resolves to that article.
func TestResolveHelpReturnsTheArticle(t *testing.T) {
	got, err := ResolveHelp("help-1", []Article{validArticle()})
	if err != nil {
		t.Fatalf("ResolveHelp error = %v", err)
	}
	if got.ID != "help-1" {
		t.Errorf("ResolveHelp returned article %q, want help-1", got.ID)
	}
	if got.Version != "2" {
		t.Errorf("Version = %q, want 2", got.Version)
	}
}

// The result is sorted by article identifier and is deterministic.
func TestHelpForIsSortedAndDeterministic(t *testing.T) {
	second := validArticle()
	second.ID = "help-0"
	articles := []Article{validArticle(), second}

	got, err := HelpFor("queue", articles)
	if err != nil {
		t.Fatalf("HelpFor error = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("HelpFor returned %d articles, want 2", len(got))
	}
	if got[0].ID != "help-0" || got[1].ID != "help-1" {
		t.Errorf("HelpFor is not sorted by identifier: %+v", got)
	}
	reversed, err := HelpFor("queue", []Article{second, validArticle()})
	if err != nil {
		t.Fatalf("HelpFor error = %v", err)
	}
	if reversed[0].ID != got[0].ID || reversed[1].ID != got[1].ID {
		t.Errorf("HelpFor is not deterministic: %+v then %+v", got, reversed)
	}
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

// A request that reuses an identifier is refused before its contents are
// considered.
func TestRegistryRefusesDuplicateRequestIdentifiers(t *testing.T) {
	r, err := (Registry{}).AddRequest(validRequest())
	if err != nil {
		t.Fatalf("AddRequest: %v", err)
	}
	if _, err := r.AddRequest(validRequest()); !errors.Is(err, ErrDuplicateRequest) {
		t.Fatalf("AddRequest error = %v, want ErrDuplicateRequest", err)
	}
}

// A request that could not be filed is not recorded.
func TestRegistryRefusesAnUnusableRequest(t *testing.T) {
	bad := validRequest()
	bad.DueAt = now.Add(72 * time.Hour)
	if _, err := (Registry{}).AddRequest(bad); !errors.Is(err, ErrDueDateMismatch) {
		t.Fatalf("AddRequest error = %v, want ErrDueDateMismatch", err)
	}
}

// Two articles under one identifier make every help link ambiguous.
func TestRegistryRefusesDuplicateArticleIdentifiers(t *testing.T) {
	r, err := (Registry{}).AddArticle(validArticle())
	if err != nil {
		t.Fatalf("AddArticle: %v", err)
	}
	if _, err := r.AddArticle(validArticle()); !errors.Is(err, ErrDuplicateArticle) {
		t.Fatalf("AddArticle error = %v, want ErrDuplicateArticle", err)
	}
}

// An article that could not be published is not recorded.
func TestRegistryRefusesAnUnusableArticle(t *testing.T) {
	bad := validArticle()
	bad.Version = ""
	if _, err := (Registry{}).AddArticle(bad); !errors.Is(err, ErrNoVersion) {
		t.Fatalf("AddArticle error = %v, want ErrNoVersion", err)
	}
}

// Nothing has to remember to file a request as overdue: the deadline and the
// moment decide it.
func TestRegistryOverdueRequests(t *testing.T) {
	late := validRequest()
	early := validRequest()
	early.ID = "req-2"
	early.Severity = communications.Sev4
	early.DueAt = now.Add(noticeWindow(communications.Sev4))
	finished := validRequest()
	finished.ID = "req-3"

	r, err := (Registry{}).AddRequest(late)
	if err != nil {
		t.Fatalf("AddRequest: %v", err)
	}
	r, err = r.AddRequest(early)
	if err != nil {
		t.Fatalf("AddRequest: %v", err)
	}
	finished, err = Resolve(finished, "the preview agent was restarted", now.Add(time.Hour))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	r, err = r.AddRequest(finished)
	if err != nil {
		t.Fatalf("AddRequest: %v", err)
	}

	overdue := r.OverdueRequests(now.Add(noticeWindow(communications.Sev3) + time.Minute))
	if len(overdue) != 1 {
		t.Fatalf("OverdueRequests returned %d requests, want 1: %+v", len(overdue), overdue)
	}
	if overdue[0].ID != "req-1" {
		t.Errorf("OverdueRequests returned request %q, want req-1", overdue[0].ID)
	}
	if got := r.OverdueRequests(now); len(got) != 0 {
		t.Errorf("OverdueRequests returned %d requests before any deadline, want 0", len(got))
	}
}

// ---------------------------------------------------------------------------
// Happy paths
// ---------------------------------------------------------------------------

// The whole request lifecycle: a request arrives with a derived deadline, the
// customer is answered, a note is written, and the request is closed with a
// note.
func TestSupportRequestLifecycle(t *testing.T) {
	r := validRequest()
	if err := r.Validate(); err != nil {
		t.Fatalf("Validate error = %v", err)
	}
	r, err := AddMessage(r, Message{At: now.Add(time.Hour), Author: "ada", Body: "we are looking at it"})
	if err != nil {
		t.Fatalf("AddMessage: %v", err)
	}
	r, err = AddComment(r, Comment{
		ID:         "c-1",
		Author:     "ada",
		Body:       "the queue is waiting on a capacity grant",
		At:         now.Add(time.Hour),
		Visibility: CommentCustomerVisible,
	})
	if err != nil {
		t.Fatalf("AddComment: %v", err)
	}
	r, err = Resolve(r, "the preview agent was restarted and the preview is ready", now.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if r.Status != RequestResolved || r.Resolution == "" {
		t.Errorf("the resolved request = %+v, want a status and a note", r)
	}
	if len(r.Messages) != 1 || len(r.Comments) != 1 {
		t.Errorf("the request holds %d messages and %d comments, want 1 and 1", len(r.Messages), len(r.Comments))
	}
	if len(ForCustomer(r.Comments)) != 1 {
		t.Error("the customer must see the customer-visible note")
	}
	if Overdue(r, now.Add(72*time.Hour)) {
		t.Error("a resolved request is never overdue")
	}
}

// The whole help surface: an article is published, a surface links to it and a
// reference resolves to it.
func TestHelpArticleLifecycle(t *testing.T) {
	r, err := (Registry{}).AddArticle(validArticle())
	if err != nil {
		t.Fatalf("AddArticle: %v", err)
	}
	help, err := HelpFor("queue", r.Articles)
	if err != nil {
		t.Fatalf("HelpFor error = %v", err)
	}
	if len(help) != 1 {
		t.Fatalf("HelpFor returned %d articles, want 1", len(help))
	}
	article, err := ResolveHelp(help[0].ID, r.Articles)
	if err != nil {
		t.Fatalf("ResolveHelp error = %v", err)
	}
	if article.ID != "help-1" || article.Version != "2" {
		t.Errorf("the resolved article = %+v, want help-1 at version 2", article)
	}
}
