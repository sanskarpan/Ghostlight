// Package consolesupport builds the customer-facing support, help, notice and
// status view the console renders.
//
// The domain packages already decide what may be shown: internal/support scopes
// requests to one organization and separates internal notes from customer-visible
// comments, and internal/communications scopes notices and refuses to call an
// unchecked component operational. Those rules are necessary but not sufficient,
// because a view model can still assemble a page that leaks one organization's
// request, drops the fact that a component is unknown, or shows a notice the
// organization is not in the audience for.
//
// This package is the place where the surfaces meet the page, so it applies the
// domain filters itself rather than trusting a caller to have applied them. The
// four properties it enforces are:
//
// The first is that **the view belongs to exactly one organization**. Requests,
// notices and acknowledgements are selected for that organization and for no
// other. An organization that names nobody gets nothing, because the empty string
// is not an organization and matching it would hand the page to whoever forgot to
// name themselves.
//
// The second is that **internal notes are a different list from customer
// comments**. A customer view carries only customer-visible comments, and a
// request's internal notes are empty. An internal view carries both, in separate
// fields, so a renderer cannot merge them by accident. The split is made from the
// domain's own visibility values, and a comment with an unknown visibility is
// refused rather than defaulted into either list.
//
// The third is that **a deadline is checked, not copied**. The view recomputes
// whether a request is overdue from its due date and the moment the page
// describes, and refuses a request whose overdue flag disagrees. A page that says
// "on time" about a request past its deadline is worse than a page that says
// nothing, because it is believed.
//
// The fourth is that **unknown is not operational**. The service-status view is
// built from the communications package's assessment, which never paints a
// component green without a fresh passing check, and this package refuses a
// component that claims a status its check time cannot support. A stale failure
// is stale rather than an outage, but stale is not green either.
//
// The view is deliberately made of copies. A caller that mutates the registries
// after building the view cannot change what the page says, and a caller that
// mutates the view cannot reach back into the domain records.
package consolesupport

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/communications"
	"github.com/sanskarpan/Ghostlight/internal/support"
)

// Errors returned by this package's view rules.
var (
	// ErrNoOrganization means the view names no organization. A page that
	// belongs to nobody belongs to whoever opens it.
	ErrNoOrganization = errors.New("support view must name an organization")
	// ErrNoMoment means the view names no moment. Overdue, notice expiry and
	// check freshness are all questions about a moment, so a view without one
	// cannot answer any of them.
	ErrNoMoment = errors.New("support view must name the moment it describes")
	// ErrInvalidRequest means a request cannot be shown without breaking one
	// of the support package's rules. The view refuses rather than drawing a
	// request whose deadline was chosen, whose conversation is out of order or
	// whose resolution is missing.
	ErrInvalidRequest = errors.New("support request cannot be shown")
	// ErrInvalidArticle means a help article cannot be shown. Help that dangles
	// or belongs to a surface the page does not name is refused when the page
	// is built, not when a customer clicks.
	ErrInvalidArticle = errors.New("help article cannot be shown")
	// ErrInvalidNotice means a notice cannot be shown. A notice that is not
	// addressed to this organization, is dated in the future or has expired is
	// not a notice the page may carry.
	ErrInvalidNotice = errors.New("notice cannot be shown")
	// ErrInvalidComponent means a component status cannot be shown. A status
	// whose check time cannot support it, or that has no reason for not being
	// operational, is refused rather than drawn as a green or unexplained row.
	ErrInvalidComponent = errors.New("component status cannot be shown")
)

// Options are the inputs the support view is built from.
//
// The organization and the moment are required. Everything else is optional: a
// page that asks for no help surfaces shows no help, and a page that names no
// components shows no status. The registries are passed separately so that the
// view can apply the domain filters itself.
type Options struct {
	// Organization is the organization the view belongs to. It is required.
	Organization string
	// Internal reports whether the viewer works on our side of the comment
	// boundary. An internal view carries internal notes in their own field; a
	// customer view never does.
	Internal bool
	// At is the moment the view describes. It is required, because overdue,
	// expiry and freshness are all arithmetic against a moment.
	At time.Time
	// Surfaces names the console screens whose help is linked from this page.
	// Every named surface must have at least one article, because a screen
	// that links to help must have help.
	Surfaces []string
	// Components names the service components that must appear on the status
	// page even when no check has run for them. A named component with no
	// check is unknown, not missing.
	Components []string
	// Checks are the status checks the components are assessed from.
	Checks []communications.StatusCheck
	// MaxCheckAge is how old a check may be and still describe the moment.
	// A check older than this makes its component unknown.
	MaxCheckAge time.Duration
}

// RequestView is one support request as the page shows it.
//
// Comments and InternalNotes are separate fields on purpose. A customer view
// carries only Comments; an internal view carries both. Keeping them apart means a
// renderer has to choose to draw the internal list, and a customer view cannot
// leak it by iterating the wrong field.
type RequestView struct {
	// ID identifies the request.
	ID string
	// Subject is the request's headline.
	Subject string
	// Body is what the customer said.
	Body string
	// Severity is how urgent the request is.
	Severity communications.Severity
	// Category is what the request is about, when it names one.
	Category string
	// Status is where the request stands.
	Status support.RequestStatus
	// ReceivedAt is when the request arrived.
	ReceivedAt time.Time
	// DueAt is the deadline derived from the severity.
	DueAt time.Time
	// Overdue reports whether the request is past its deadline and still live.
	Overdue bool
	// ResolvedAt is when the request was resolved. It is zero while live.
	ResolvedAt time.Time
	// Resolution says what resolved the request. It is empty while live.
	Resolution string
	// Messages is the conversation with the customer, oldest first.
	Messages []support.Message
	// Comments are the customer-visible comments, oldest first.
	Comments []support.Comment
	// InternalNotes are our own notes, oldest first. They are empty on a
	// customer view.
	InternalNotes []support.Comment
}

// NoticeView is one notice as the page shows it.
//
// The view carries this organization's acknowledgement only. It does not carry the
// audience or any other organization's acknowledgement, because who has seen a
// notice is not the notice's business to disclose.
type NoticeView struct {
	// ID identifies the notice.
	ID string
	// Title is the notice's headline.
	Title string
	// Body is the notice's text.
	Body string
	// Kind is what kind of notice this is.
	Kind communications.NoticeKind
	// Severity is how bad the thing being announced is, when it names one.
	Severity communications.Severity
	// PublishedAt is when the notice was published.
	PublishedAt time.Time
	// ExpiresAt is when the notice stops being true.
	ExpiresAt time.Time
	// Acknowledged reports whether this organization has acknowledged it.
	Acknowledged bool
}

// View is the support surfaces as one console page shows them.
type View struct {
	// Organization is the organization the page belongs to.
	Organization string
	// Internal reports whether the viewer may read internal notes.
	Internal bool
	// At is the moment the page describes.
	At time.Time
	// MaxCheckAge is the freshness bound the status was assessed against.
	MaxCheckAge time.Duration
	// Surfaces are the help surfaces the page links to.
	Surfaces []string
	// Requests are the organization's support requests, sorted by identifier.
	Requests []RequestView
	// Help are the articles for the named surfaces, sorted by identifier.
	Help []support.Article
	// Notices are the notices addressed to the organization, newest first.
	Notices []NoticeView
	// Status is the service status, sorted by component name.
	Status []communications.Component
}

// Build assembles the support surfaces for one organization.
//
// The domain filters are applied here rather than by the caller. Requests and
// notices are scoped to the organization, internal notes are separated from
// customer comments, expired notices are dropped, and the service status is
// assessed from the checks rather than copied from a stored verdict.
//
// The result is deterministic: the same registries and options produce the same
// view whatever order the inputs arrived in. Requests, help and status are sorted
// by identifier or name, and notices are sorted newest first.
func Build(requests support.Registry, comms communications.Registry, opts Options) (View, error) {
	organization := strings.TrimSpace(opts.Organization)
	if organization == "" {
		return View{}, ErrNoOrganization
	}
	if opts.At.IsZero() {
		return View{}, ErrNoMoment
	}
	at := opts.At.UTC()

	requestViews, err := buildRequests(requests.Requests, organization, opts.Internal, at)
	if err != nil {
		return View{}, err
	}
	articles, surfaces, err := buildHelp(requests.Articles, opts.Surfaces)
	if err != nil {
		return View{}, err
	}
	notices, err := buildNotices(comms, organization, at)
	if err != nil {
		return View{}, err
	}
	components, err := buildStatus(opts)
	if err != nil {
		return View{}, err
	}

	view := View{
		Organization: organization,
		Internal:     opts.Internal,
		At:           at,
		MaxCheckAge:  opts.MaxCheckAge,
		Surfaces:     surfaces,
		Requests:     requestViews,
		Help:         articles,
		Notices:      notices,
		Status:       components,
	}
	if err := view.Validate(); err != nil {
		return View{}, err
	}
	return view, nil
}

// buildRequests scopes the requests to the organization and copies the fields the
// page shows.
//
// The request's own Validate is called before anything is copied, so a request
// whose due date was chosen rather than derived is refused even if it arrived in a
// registry that never checked it. Comments are split by visibility after every
// comment has been validated, so an unknown visibility cannot fall through into
// either list.
func buildRequests(requests []support.Request, organization string, internal bool, at time.Time) ([]RequestView, error) {
	visible := support.VisibleTo(requests, organization)
	sort.Slice(visible, func(i, j int) bool { return visible[i].ID < visible[j].ID })

	out := make([]RequestView, 0, len(visible))
	for _, req := range visible {
		if err := req.Validate(); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidRequest, err)
		}
		status := req.Status
		if status == "" {
			status = support.RequestOpen
		}
		if err := validateRequestState(req, status); err != nil {
			return nil, err
		}
		if err := validateMessages(req); err != nil {
			return nil, err
		}
		customer, notes, err := splitComments(req, internal)
		if err != nil {
			return nil, err
		}
		out = append(out, RequestView{
			ID:            req.ID,
			Subject:       req.Subject,
			Body:          req.Body,
			Severity:      req.Severity,
			Category:      req.Category,
			Status:        status,
			ReceivedAt:    req.ReceivedAt,
			DueAt:         req.DueAt,
			Overdue:       support.Overdue(req, at),
			ResolvedAt:    req.ResolvedAt,
			Resolution:    req.Resolution,
			Messages:      append([]support.Message{}, req.Messages...),
			Comments:      customer,
			InternalNotes: notes,
		})
	}
	return out, nil
}

// validateRequestState refuses a request whose status and resolution disagree.
//
// A resolved request without a note is the failure the support package exists to
// prevent, and a live request carrying a resolution has a record that says two
// things at once. Both are refused rather than drawn as if they made sense.
func validateRequestState(req support.Request, status support.RequestStatus) error {
	switch status {
	case support.RequestOpen, support.RequestPending:
		if strings.TrimSpace(req.Resolution) != "" || !req.ResolvedAt.IsZero() {
			return fmt.Errorf("%w: request %q is %s but carries a resolution", ErrInvalidRequest, req.ID, status)
		}
	case support.RequestResolved:
		if strings.TrimSpace(req.Resolution) == "" {
			return fmt.Errorf("%w: request %q is resolved without a resolution note", ErrInvalidRequest, req.ID)
		}
		if req.ResolvedAt.IsZero() {
			return fmt.Errorf("%w: request %q is resolved without a resolution time", ErrInvalidRequest, req.ID)
		}
	default:
		return fmt.Errorf("%w: request %q carries unknown status %q", ErrInvalidRequest, req.ID, status)
	}
	return nil
}

// validateMessages refuses a conversation that cannot be read as a conversation.
//
// The support package refuses an empty message, a message nobody wrote and a
// message dated before the request arrived. This repeats those checks because a
// request can arrive in the view from a store that never went through AddMessage,
// and adds the ordering check that makes the thread a thread.
func validateMessages(req support.Request) error {
	var last time.Time
	for i, message := range req.Messages {
		if strings.TrimSpace(message.Body) == "" {
			return fmt.Errorf("%w: message %d on request %q has no body", ErrInvalidRequest, i+1, req.ID)
		}
		if strings.TrimSpace(message.Author) == "" {
			return fmt.Errorf("%w: message %d on request %q has no author", ErrInvalidRequest, i+1, req.ID)
		}
		if message.At.Before(req.ReceivedAt) {
			return fmt.Errorf("%w: message %d on request %q is dated before the request arrived", ErrInvalidRequest, i+1, req.ID)
		}
		if i > 0 && message.At.Before(last) {
			return fmt.Errorf("%w: messages on request %q are not in time order", ErrInvalidRequest, req.ID)
		}
		last = message.At
	}
	return nil
}

// splitComments validates every comment and separates the customer-visible ones
// from our own notes.
//
// ForCustomer is the only way to get the customer list, so a caller cannot forget
// to apply the visibility rule. The internal list is built from the same validated
// set and is empty unless the viewer is internal.
func splitComments(req support.Request, internal bool) ([]support.Comment, []support.Comment, error) {
	seen := map[string]bool{}
	var last time.Time
	for _, comment := range req.Comments {
		if err := comment.Validate(); err != nil {
			return nil, nil, fmt.Errorf("%w: %w", ErrInvalidRequest, err)
		}
		if seen[comment.ID] {
			return nil, nil, fmt.Errorf("%w: request %q has duplicate comment %q", ErrInvalidRequest, req.ID, comment.ID)
		}
		seen[comment.ID] = true
		if !last.IsZero() && comment.At.Before(last) {
			return nil, nil, fmt.Errorf("%w: comments on request %q are not in time order", ErrInvalidRequest, req.ID)
		}
		last = comment.At
	}

	customer := support.ForCustomer(req.Comments)
	var notes []support.Comment
	if internal {
		for _, comment := range req.Comments {
			if comment.Visibility == support.CommentInternal {
				notes = append(notes, comment)
			}
		}
	}
	if customer == nil {
		customer = []support.Comment{}
	}
	if notes == nil {
		notes = []support.Comment{}
	}
	return customer, notes, nil
}

// buildHelp validates the article set and collects the help for every named
// surface.
//
// A surface with no articles is refused rather than answered with an empty list,
// because a screen that links to help must have help. The surface names are
// sorted and deduplicated so the view is deterministic.
func buildHelp(articles []support.Article, surfaces []string) ([]support.Article, []string, error) {
	if err := support.ValidateArticles(articles); err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrInvalidArticle, err)
	}
	seen := map[string]bool{}
	var names []string
	for _, surface := range surfaces {
		name := strings.TrimSpace(surface)
		if name == "" {
			return nil, nil, fmt.Errorf("%w: no surface named", ErrInvalidArticle)
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		names = append(names, name)
	}
	sort.Strings(names)

	var out []support.Article
	for _, name := range names {
		found, err := support.HelpFor(name, articles)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %w", ErrInvalidArticle, err)
		}
		out = append(out, found...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	if out == nil {
		out = []support.Article{}
	}
	if names == nil {
		names = []string{}
	}
	return out, names, nil
}

// buildNotices scopes the notices to the organization and keeps only the ones
// that are live at the moment the page describes.
//
// NoticesFor already removes notices addressed to somebody else and strips every
// acknowledgement but this organization's. An expired notice is dropped because a
// notice past its expiry is not a notice any more; a notice dated after the moment
// is refused rather than shown early, because its publication time would then be
// a claim about the future.
func buildNotices(comms communications.Registry, organization string, at time.Time) ([]NoticeView, error) {
	visible := comms.NoticesFor(organization)
	out := make([]NoticeView, 0, len(visible))
	for _, notice := range visible {
		if err := notice.Validate(); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidNotice, err)
		}
		if notice.PublishedAt.After(at) {
			return nil, fmt.Errorf("%w: notice %q is published after the moment the page describes", ErrInvalidNotice, notice.ID)
		}
		if !notice.ExpiresAt.After(at) {
			continue
		}
		out = append(out, NoticeView{
			ID:           notice.ID,
			Title:        notice.Title,
			Body:         notice.Body,
			Kind:         notice.Kind,
			Severity:     notice.Severity,
			PublishedAt:  notice.PublishedAt,
			ExpiresAt:    notice.ExpiresAt,
			Acknowledged: communications.AcknowledgedBy(notice, organization),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].PublishedAt.Equal(out[j].PublishedAt) {
			return out[i].PublishedAt.After(out[j].PublishedAt)
		}
		return out[i].ID < out[j].ID
	})
	if out == nil {
		out = []NoticeView{}
	}
	return out, nil
}

// buildStatus assesses the service status from the checks.
//
// AssessComponents is what makes unknown explicit: a named component with no
// check, or a check older than the freshness bound, is unknown rather than
// missing. The view refuses a component whose status the assessment could not
// have produced, so a hand-built status cannot claim a green row without a fresh
// passing check.
func buildStatus(opts Options) ([]communications.Component, error) {
	components := communications.AssessComponents(opts.Components, opts.Checks, opts.At, opts.MaxCheckAge)
	for _, component := range components {
		if err := validateComponent(component, opts.At, opts.MaxCheckAge); err != nil {
			return nil, err
		}
	}
	if components == nil {
		components = []communications.Component{}
	}
	return components, nil
}

// Validate refuses a view that would mislead a reader.
//
// The builder already applies these rules; Validate exists so that a view
// constructed by hand, or mutated after construction, cannot reach a renderer
// carrying an internal note on a customer page, an overdue flag that disagrees
// with the deadline, or a component status its check time cannot support.
func (v View) Validate() error {
	if strings.TrimSpace(v.Organization) == "" {
		return ErrNoOrganization
	}
	if v.At.IsZero() {
		return ErrNoMoment
	}

	seenRequests := map[string]bool{}
	for _, request := range v.Requests {
		if err := request.Validate(v.At); err != nil {
			return err
		}
		if seenRequests[request.ID] {
			return fmt.Errorf("%w: duplicate request %q", ErrInvalidRequest, request.ID)
		}
		seenRequests[request.ID] = true
		if !v.Internal && len(request.InternalNotes) > 0 {
			return fmt.Errorf("%w: request %q carries internal notes on a customer view", ErrInvalidRequest, request.ID)
		}
	}

	if err := support.ValidateArticles(v.Help); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidArticle, err)
	}
	surfaces := map[string]bool{}
	for _, surface := range v.Surfaces {
		surfaces[strings.TrimSpace(surface)] = true
	}
	seenArticles := map[string]bool{}
	for _, article := range v.Help {
		if seenArticles[article.ID] {
			return fmt.Errorf("%w: duplicate article %q", ErrInvalidArticle, article.ID)
		}
		seenArticles[article.ID] = true
		if !surfaces[strings.TrimSpace(article.Surface)] {
			return fmt.Errorf("%w: article %q is for surface %q, which the view does not name",
				ErrInvalidArticle, article.ID, article.Surface)
		}
	}

	seenNotices := map[string]bool{}
	for _, notice := range v.Notices {
		if err := notice.Validate(v.At); err != nil {
			return err
		}
		if seenNotices[notice.ID] {
			return fmt.Errorf("%w: duplicate notice %q", ErrInvalidNotice, notice.ID)
		}
		seenNotices[notice.ID] = true
	}

	seenComponents := map[string]bool{}
	for _, component := range v.Status {
		if err := validateComponent(component, v.At, v.MaxCheckAge); err != nil {
			return err
		}
		if seenComponents[component.Name] {
			return fmt.Errorf("%w: duplicate component %q", ErrInvalidComponent, component.Name)
		}
		seenComponents[component.Name] = true
	}
	return nil
}

// Validate refuses a request view whose fields cannot all be true at once.
//
// The due date is recomputed from the severity and the received time, because a
// deadline that was chosen rather than derived is the failure the support package
// exists to prevent. The overdue flag is recomputed from the deadline and the
// moment, because a page that says "on time" about a late request is believed.
func (r RequestView) Validate(at time.Time) error {
	if strings.TrimSpace(r.ID) == "" {
		return fmt.Errorf("%w: request has no identifier", ErrInvalidRequest)
	}
	if strings.TrimSpace(r.Subject) == "" {
		return fmt.Errorf("%w: request %q has no subject", ErrInvalidRequest, r.ID)
	}
	if strings.TrimSpace(r.Body) == "" {
		return fmt.Errorf("%w: request %q has no body", ErrInvalidRequest, r.ID)
	}
	if _, err := communications.DefinitionFor(r.Severity); err != nil {
		return fmt.Errorf("%w: request %q: %w", ErrInvalidRequest, r.ID, err)
	}
	if r.ReceivedAt.IsZero() {
		return fmt.Errorf("%w: request %q has no received time", ErrInvalidRequest, r.ID)
	}
	due, err := support.DueAt(r.ReceivedAt, r.Severity)
	if err != nil {
		return fmt.Errorf("%w: request %q: %w", ErrInvalidRequest, r.ID, err)
	}
	if !r.DueAt.Equal(due) {
		return fmt.Errorf("%w: request %q is due at %s but the %s commitment makes it due at %s",
			ErrInvalidRequest, r.ID, stamp(r.DueAt), r.Severity, stamp(due))
	}
	if err := validateRequestState(support.Request{
		ID:         r.ID,
		Status:     r.Status,
		ResolvedAt: r.ResolvedAt,
		Resolution: r.Resolution,
	}, r.Status); err != nil {
		return err
	}
	wantOverdue := support.Overdue(support.Request{Status: r.Status, DueAt: r.DueAt}, at)
	if r.Overdue != wantOverdue {
		return fmt.Errorf("%w: request %q says overdue=%t but its deadline says %t",
			ErrInvalidRequest, r.ID, r.Overdue, wantOverdue)
	}
	if err := validateMessages(support.Request{
		ID:         r.ID,
		ReceivedAt: r.ReceivedAt,
		Messages:   r.Messages,
	}); err != nil {
		return err
	}
	return validateCommentLists(r)
}

// validateCommentLists refuses a request whose customer and internal comment
// lists do not match their names.
//
// A customer-visible comment in the internal list would be hidden from the
// customer who wrote it, and an internal note in the customer list would leak.
// Both are refused rather than reclassified, because reclassifying would guess at
// the author's intent.
func validateCommentLists(r RequestView) error {
	seen := map[string]bool{}
	for _, list := range [][]support.Comment{r.Comments, r.InternalNotes} {
		var last time.Time
		for _, comment := range list {
			if err := comment.Validate(); err != nil {
				return fmt.Errorf("%w: %w", ErrInvalidRequest, err)
			}
			if seen[comment.ID] {
				return fmt.Errorf("%w: request %q has duplicate comment %q", ErrInvalidRequest, r.ID, comment.ID)
			}
			seen[comment.ID] = true
			if !last.IsZero() && comment.At.Before(last) {
				return fmt.Errorf("%w: comments on request %q are not in time order", ErrInvalidRequest, r.ID)
			}
			last = comment.At
		}
	}
	for _, comment := range r.Comments {
		if comment.Visibility != support.CommentCustomerVisible {
			return fmt.Errorf("%w: request %q carries comment %q in the customer list with visibility %q",
				ErrInvalidRequest, r.ID, comment.ID, comment.Visibility)
		}
	}
	for _, comment := range r.InternalNotes {
		if comment.Visibility != support.CommentInternal {
			return fmt.Errorf("%w: request %q carries comment %q in the internal list with visibility %q",
				ErrInvalidRequest, r.ID, comment.ID, comment.Visibility)
		}
	}
	return nil
}

// Validate refuses a notice view whose dates cannot all be true at once.
func (n NoticeView) Validate(at time.Time) error {
	if strings.TrimSpace(n.ID) == "" {
		return fmt.Errorf("%w: notice has no identifier", ErrInvalidNotice)
	}
	if strings.TrimSpace(n.Title) == "" {
		return fmt.Errorf("%w: notice %q has no title", ErrInvalidNotice, n.ID)
	}
	switch n.Kind {
	case communications.NoticeAdvisory, communications.NoticeMaintenance, communications.NoticeIncident:
	default:
		return fmt.Errorf("%w: notice %q carries unknown kind %q", ErrInvalidNotice, n.ID, n.Kind)
	}
	if n.Severity != "" {
		if _, err := communications.DefinitionFor(n.Severity); err != nil {
			return fmt.Errorf("%w: notice %q: %w", ErrInvalidNotice, n.ID, err)
		}
	}
	if n.PublishedAt.IsZero() {
		return fmt.Errorf("%w: notice %q was never published", ErrInvalidNotice, n.ID)
	}
	if n.ExpiresAt.IsZero() {
		return fmt.Errorf("%w: notice %q has no expiry", ErrInvalidNotice, n.ID)
	}
	if !n.ExpiresAt.After(n.PublishedAt) {
		return fmt.Errorf("%w: notice %q expires before it was published", ErrInvalidNotice, n.ID)
	}
	if n.PublishedAt.After(at) {
		return fmt.Errorf("%w: notice %q is published after the moment the page describes", ErrInvalidNotice, n.ID)
	}
	if !n.ExpiresAt.After(at) {
		return fmt.Errorf("%w: notice %q has expired", ErrInvalidNotice, n.ID)
	}
	return nil
}

// validateComponent refuses a status row the checks cannot support.
//
// A component that is not operational must say why, because a grey or red row
// with no reason leaves the reader guessing. A component that is operational must
// have a fresh passing check, because a green row with no check is the lie the
// status page exists to prevent. Maintenance is allowed without a fresh check:
// planned work is a statement about intent, not a claim about a passing check.
func validateComponent(component communications.Component, at time.Time, maxAge time.Duration) error {
	if strings.TrimSpace(component.Name) == "" {
		return fmt.Errorf("%w: component has no name", ErrInvalidComponent)
	}
	switch component.Status {
	case communications.StatusOperational, communications.StatusDegraded,
		communications.StatusOutage, communications.StatusMaintenance, communications.StatusUnknown:
	default:
		return fmt.Errorf("%w: component %q carries unknown status %q", ErrInvalidComponent, component.Name, component.Status)
	}
	if component.Status != communications.StatusOperational && strings.TrimSpace(component.Reason) == "" {
		return fmt.Errorf("%w: component %q is %s with no reason", ErrInvalidComponent, component.Name, component.Status)
	}
	if component.Status == communications.StatusMaintenance {
		if !component.LastCheckedAt.IsZero() && component.LastCheckedAt.After(at) {
			return fmt.Errorf("%w: component %q has a check dated after the moment the page describes",
				ErrInvalidComponent, component.Name)
		}
		return nil
	}
	if component.LastCheckedAt.IsZero() {
		if component.Status != communications.StatusUnknown {
			return fmt.Errorf("%w: component %q is %s with no check", ErrInvalidComponent, component.Name, component.Status)
		}
		return nil
	}
	if component.LastCheckedAt.After(at) {
		return fmt.Errorf("%w: component %q has a check dated after the moment the page describes",
			ErrInvalidComponent, component.Name)
	}
	if at.Sub(component.LastCheckedAt) > maxAge && component.Status != communications.StatusUnknown {
		return fmt.Errorf("%w: component %q is %s but its check is older than the freshness bound",
			ErrInvalidComponent, component.Name, component.Status)
	}
	return nil
}

// stamp renders a moment the way refusals name it, in UTC.
func stamp(at time.Time) string {
	if at.IsZero() {
		return "no time"
	}
	return at.UTC().Format(time.RFC3339)
}
