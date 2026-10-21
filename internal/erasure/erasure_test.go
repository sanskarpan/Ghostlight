package erasure

import (
	"errors"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 11, 4, 9, 0, 0, 0, time.UTC)

// scripted erases on demand and can fail or fail to confirm.
type scripted struct {
	fail      map[string]error
	unconfirm map[string]bool
	erased    []string
}

func (s *scripted) Erase(kind ItemKind, recordID string) (bool, error) {
	s.erased = append(s.erased, recordID)
	if err, ok := s.fail[recordID]; ok {
		return false, err
	}
	if s.unconfirm[recordID] {
		return false, nil
	}
	return true, nil
}

// job is a small closure: a table, the record inside it, and a credential.
func job() Job {
	return Job{
		ID:           "erase-1",
		Organization: "org-1",
		RequestedBy:  "ada",
		Reason:       "organization closure",
		RequestedAt:  now,
		Items: []Item{
			{RecordID: "table-users", Kind: KindTable},
			{RecordID: "record-1", Kind: KindRecord, DependsOn: []string{"table-users"}},
			{RecordID: "cred-1", Kind: KindCredential},
		},
	}
}

// ---------------------------------------------------------------------------
// Job shape
// ---------------------------------------------------------------------------

func TestJobRefusesUnusableShapes(t *testing.T) {
	cases := map[string]struct {
		mutate func(*Job)
		want   error
	}{
		"no identifier":              {func(j *Job) { j.ID = "" }, ErrNoJobID},
		"no organization":            {func(j *Job) { j.Organization = "" }, ErrNoOrganization},
		"no actor":                   {func(j *Job) { j.RequestedBy = "" }, ErrNoActor},
		"no items":                   {func(j *Job) { j.Items = nil }, ErrNoItems},
		"no record id":               {func(j *Job) { j.Items[0].RecordID = "  " }, ErrUnknownItem},
		"duplicate item":             {func(j *Job) { j.Items[1].RecordID = j.Items[0].RecordID }, ErrDuplicateItem},
		"dependency outside the job": {func(j *Job) { j.Items[0].DependsOn = []string{"not-here"} }, ErrUnknownDependency},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			j := job()
			tc.mutate(&j)
			if _, err := j.Order(); !errors.Is(err, tc.want) {
				t.Errorf("Order error = %v, want %v", err, tc.want)
			}
			if _, _, err := Run(j, &scripted{}, NewJournal("org-1"), now); !errors.Is(err, tc.want) {
				t.Errorf("Run error = %v, want %v", err, tc.want)
			}
		})
	}
}

// A dependent is erased after its dependency, never before.
func TestOrderPutsDependenciesFirst(t *testing.T) {
	order, err := job().Order()
	if err != nil {
		t.Fatalf("Order: %v", err)
	}
	position := map[string]int{}
	for i, item := range order {
		position[item.RecordID] = i
	}
	if position["table-users"] > position["record-1"] {
		t.Errorf("order = %v, want the table before the record that lives in it", order)
	}
	if len(order) != 3 {
		t.Errorf("order = %v, want every item", order)
	}
}

// An arbitrary break of a cycle means one record is erased while the other still
// refers to it, and neither of those states is one anybody can describe.
func TestOrderRefusesADependencyCycle(t *testing.T) {
	j := job()
	j.Items[0].DependsOn = []string{"record-1"}
	if _, err := j.Order(); !errors.Is(err, ErrDependencyCycle) {
		t.Errorf("Order error = %v, want ErrDependencyCycle", err)
	}
}

// The order is deterministic, so two runs of the same job erase in the same sequence.
func TestOrderIsDeterministic(t *testing.T) {
	j := job()
	j.Items = append(j.Items, Item{RecordID: "object-1", Kind: KindObject})
	first, err := j.Order()
	if err != nil {
		t.Fatalf("Order: %v", err)
	}
	second, err := j.Order()
	if err != nil {
		t.Fatalf("Order: %v", err)
	}
	for i := range first {
		if first[i].RecordID != second[i].RecordID {
			t.Fatalf("orders differ: %v and %v", first, second)
		}
	}
}

// ---------------------------------------------------------------------------
// Running the job
// ---------------------------------------------------------------------------

// A delete that returned successfully is not evidence, so an unconfirmed erasure
// stays outstanding rather than being counted as erased.
func TestUnconfirmedErasureStaysOutstanding(t *testing.T) {
	e := &scripted{unconfirm: map[string]bool{"record-1": true}}
	report, journal, err := Run(job(), e, NewJournal("org-1"), now)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if _, ok := report.Outstanding["record-1"]; !ok {
		t.Errorf("outstanding = %v, want the unconfirmed record listed", report.Outstanding)
	}
	if _, ok := journal.Erased["record-1"]; ok {
		t.Error("an unconfirmed erasure must not be journaled as erased")
	}
	if report.Complete {
		t.Error("a job with an unconfirmed erasure is not complete")
	}
	if len(report.Erased) != 2 {
		t.Errorf("erased = %v, want the two confirmed records", report.Erased)
	}
}

// A job that erased four of five is not complete, and the report says four.
func TestPartialErasureIsReportedHonestly(t *testing.T) {
	e := &scripted{fail: map[string]error{"cred-1": errors.New("provider refused")}}
	report, journal, err := Run(job(), e, NewJournal("org-1"), now)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if report.Complete {
		t.Error("a partial erasure must not report complete")
	}
	if len(report.Erased) != 2 {
		t.Errorf("erased = %v, want the two that succeeded", report.Erased)
	}
	if len(report.Outstanding) != 1 {
		t.Errorf("outstanding = %v, want the one that failed", report.Outstanding)
	}
	if !strings.Contains(report.Outstanding["cred-1"], "provider refused") {
		t.Errorf("the reason must be carried, got %q", report.Outstanding["cred-1"])
	}
	if _, ok := journal.Outstanding["cred-1"]; !ok {
		t.Error("the failure must be journaled as outstanding")
	}
}

// Erasing twice is harmless; erasing a half-erased set and reporting success is not.
func TestJobIsResumableAfterAnInterruption(t *testing.T) {
	e := &scripted{fail: map[string]error{"cred-1": errors.New("transient")}}
	_, journal, err := Run(job(), e, NewJournal("org-1"), now)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(journal.Erased) != 2 {
		t.Fatalf("journal = %v, want two erased", journal.Erased)
	}

	// Re-run with a working eraser. The two already erased are skipped.
	second := &scripted{}
	report, journal, err := Run(job(), second, journal, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if !report.Complete {
		t.Error("the resumed job must complete")
	}
	if len(second.erased) != 1 || second.erased[0] != "cred-1" {
		t.Errorf("the resumed job erased %v, want only the outstanding record", second.erased)
	}
	if len(journal.Erased) != 3 {
		t.Errorf("journal = %v, want all three erased", journal.Erased)
	}
	if len(journal.Outstanding) != 0 {
		t.Errorf("outstanding = %v, want none", journal.Outstanding)
	}
}

func TestRunRefusesAMismatchedJournal(t *testing.T) {
	if _, _, err := Run(job(), &scripted{}, NewJournal("org-2"), now); !errors.Is(err, ErrUnknownOrganization) {
		t.Errorf("Run error = %v, want ErrUnknownOrganization", err)
	}
}

func TestRunRefusesAnAbsentEraser(t *testing.T) {
	if _, _, err := Run(job(), nil, NewJournal("org-1"), now); err == nil {
		t.Error("expected the run to be refused without an eraser")
	}
}

// ---------------------------------------------------------------------------
// Post-recovery replay
// ---------------------------------------------------------------------------

// A restore brings back everything that was in the backup, including records erased
// after it was taken. The journal and the restored state disagree, and the
// disagreement is exactly the set that must go again.
func TestReplayErasesRecordsThatCameBack(t *testing.T) {
	e := &scripted{}
	_, journal, err := Run(job(), e, NewJournal("org-1"), now)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// The platform was restored from a backup taken before the erasure.
	restored := []Item{
		{RecordID: "table-users", Kind: KindTable},
		{RecordID: "record-1", Kind: KindRecord},
		{RecordID: "cred-1", Kind: KindCredential},
	}
	replayEraser := &scripted{}
	result, journal, err := Replay(journal, restored, replayEraser, now.Add(24*time.Hour))
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if len(result.Findings) != 3 {
		t.Fatalf("findings = %v, want the three erased records found again", result.Findings)
	}
	if !result.Resolved {
		t.Error("the replay must resolve when every record was erased again")
	}
	if len(replayEraser.erased) != 3 {
		t.Errorf("re-erased %v, want all three", replayEraser.erased)
	}
	if len(journal.Outstanding) != 0 {
		t.Errorf("outstanding = %v, want none", journal.Outstanding)
	}
}

// A record that was never erased is not the replay's business.
func TestReplayIgnoresRecordsThatWereNeverErased(t *testing.T) {
	journal := NewJournal("org-1")
	journal.Erased["record-1"] = now
	replayEraser := &scripted{}
	result, _, err := Replay(journal, []Item{
		{RecordID: "never-erased", Kind: KindRecord},
	}, replayEraser, now)
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("findings = %v, want none", result.Findings)
	}
	if len(replayEraser.erased) != 0 {
		t.Errorf("erased %v, want nothing", replayEraser.erased)
	}
}

// "We tried" is not "we did", and a report that rounds a failure up to a success is the
// failure this package exists to prevent.
func TestReplayReportsWhatItCouldNotEraseAgain(t *testing.T) {
	journal := NewJournal("org-1")
	journal.Erased["record-1"] = now
	journal.Erased["cred-1"] = now
	replayEraser := &scripted{fail: map[string]error{"cred-1": errors.New("still locked")}}
	result, journal, err := Replay(journal, []Item{
		{RecordID: "record-1", Kind: KindRecord},
		{RecordID: "cred-1", Kind: KindCredential},
	}, replayEraser, now)
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if result.Resolved {
		t.Error("the replay must not resolve when a record could not be erased again")
	}
	if len(result.Findings) != 2 {
		t.Fatalf("findings = %v, want both records reported", result.Findings)
	}
	for _, f := range result.Findings {
		if f.RecordID == "cred-1" {
			if f.ReErasable {
				t.Error("the failed record must not be reported as re-erased")
			}
			if !strings.Contains(f.Reason, "still locked") {
				t.Errorf("reason = %q, want the provider's own", f.Reason)
			}
		}
		if f.RecordID == "record-1" && !f.ReErasable {
			t.Error("the successful record must be reported as re-erased")
		}
	}
	if _, ok := journal.Outstanding["cred-1"]; !ok {
		t.Error("the unresolved record must be journaled as outstanding")
	}
}

// An unconfirmed re-erasure is not a re-erasure.
func TestReplayTreatsUnconfirmedAsUnresolved(t *testing.T) {
	journal := NewJournal("org-1")
	journal.Erased["record-1"] = now
	replayEraser := &scripted{unconfirm: map[string]bool{"record-1": true}}
	result, _, err := Replay(journal, []Item{{RecordID: "record-1", Kind: KindRecord}}, replayEraser, now)
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if result.Resolved {
		t.Error("an unconfirmed re-erasure must not resolve")
	}
}

func TestReplayRefusesAnAbsentEraserAndEmptyJournal(t *testing.T) {
	if _, _, err := Replay(NewJournal("org-1"), nil, &scripted{}, now); err != nil {
		t.Errorf("Replay with no records must not fail: %v", err)
	}
	if _, _, err := Replay(NewJournal("org-1"), []Item{{RecordID: "r"}}, nil, now); err == nil {
		t.Error("expected the replay to be refused without an eraser")
	}
	if _, _, err := Replay(Journal{}, []Item{{RecordID: "r"}}, &scripted{}, now); !errors.Is(err, ErrUnknownOrganization) {
		t.Errorf("Replay error = %v, want ErrUnknownOrganization", err)
	}
}

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

// Erase an organization, confirm every item, restore from a stale backup, and confirm
// the replay erases the records that came back — leaving the closure true.
func TestHappyPathEraseThenReplayAfterRestore(t *testing.T) {
	e := &scripted{}
	report, journal, err := Run(job(), e, NewJournal("org-1"), now)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !report.Complete {
		t.Fatalf("report = %+v, want a complete erasure", report)
	}
	if len(report.Erased) != 3 {
		t.Errorf("erased = %v, want all three", report.Erased)
	}
	if len(e.erased) != 3 {
		t.Errorf("the eraser saw %v, want all three", e.erased)
	}

	// A restore from a backup taken before the erasure brings everything back.
	replayEraser := &scripted{}
	result, journal, err := Replay(journal, []Item{
		{RecordID: "table-users", Kind: KindTable},
		{RecordID: "record-1", Kind: KindRecord},
		{RecordID: "cred-1", Kind: KindCredential},
	}, replayEraser, now.Add(24*time.Hour))
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if !result.Resolved {
		t.Fatalf("result = %+v, want the replay to resolve", result)
	}
	if len(result.Findings) != 3 {
		t.Errorf("findings = %v, want all three records found again", result.Findings)
	}
	if len(journal.Erased) != 3 || len(journal.Outstanding) != 0 {
		t.Errorf("journal = %+v, want everything erased and nothing outstanding", journal)
	}
}
