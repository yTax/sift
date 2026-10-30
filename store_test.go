package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testStore(t *testing.T, dir string) *Store {
	t.Helper()
	st, err := openStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	st := testStore(t, dir)
	st.With(func(repos map[string]*Repo) {
		repos["gh:a/b"] = &Repo{Key: "gh:a/b", Source: "github", Status: "new", Score: &Score{Total: 42}, Filter: FilterResult{Pass: true}}
		repos["gh:c/d"] = &Repo{Key: "gh:c/d", Source: "github", Status: "skipped"}
	})
	id := st.AddRun(RunRecord{Started: time.Now(), Stages: []string{"scan"}})
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	st2 := testStore(t, dir)
	r, ok := st2.Get("gh:a/b")
	if !ok || r.Score == nil || r.Score.Total != 42 || !r.Filter.Pass {
		t.Fatalf("gh:a/b after reopen = %+v, %v", r, ok)
	}
	if runs := st2.Runs(); len(runs) != 1 || runs[0].ID != id || runs[0].Stages[0] != "scan" {
		t.Fatalf("runs after reopen = %+v", runs)
	}

	// update one, delete the other
	st2.With(func(repos map[string]*Repo) {
		repos["gh:a/b"].Status = "digging"
		delete(repos, "gh:c/d")
	})
	if err := st2.Close(); err != nil {
		t.Fatal(err)
	}
	st3 := testStore(t, dir)
	if r, _ := st3.Get("gh:a/b"); r.Status != "digging" {
		t.Errorf("status = %q, want digging", r.Status)
	}
	if _, ok := st3.Get("gh:c/d"); ok {
		t.Error("deleted repo came back")
	}
	var status string
	if err := st3.db.QueryRow(`SELECT status FROM repos WHERE key = 'gh:a/b'`).Scan(&status); err != nil || status != "digging" {
		t.Errorf("status column = %q (%v), want digging", status, err)
	}
}

// A save must only write rows whose repo changed: that's the whole point of leaving state.json.
func TestStoreWritesOnlyChangedRows(t *testing.T) {
	st := testStore(t, t.TempDir())
	st.With(func(repos map[string]*Repo) {
		repos["gh:a/b"] = &Repo{Key: "gh:a/b", Source: "github", Status: "new"}
		repos["gh:c/d"] = &Repo{Key: "gh:c/d", Source: "github", Status: "new"}
	})
	if err := st.SaveNow(); err != nil {
		t.Fatal(err)
	}
	// mark both rows behind the store's back; a rewrite of a row would wipe its mark
	if _, err := st.db.Exec(`UPDATE repos SET source = 'untouched'`); err != nil {
		t.Fatal(err)
	}
	st.With(func(repos map[string]*Repo) { repos["gh:a/b"].Notes = "changed" })
	if err := st.SaveNow(); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	rows, err := st.db.Query(`SELECT key, source FROM repos`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var k, s string
		rows.Scan(&k, &s)
		got[k] = s
	}
	if got["gh:a/b"] != "github" || got["gh:c/d"] != "untouched" {
		t.Errorf("sources after save = %v, want only gh:a/b rewritten", got)
	}
}

func TestStoreImportsStateFile(t *testing.T) {
	dir := t.TempDir()
	sf := stateFile{
		Repos: map[string]*Repo{"wp:x": {Key: "wp:x", Source: "wordpress", Status: "shortlist", Notes: "look at ajax"}},
		Runs:  []RunRecord{{ID: 7, Outcome: "finished"}},
	}
	b, _ := json.Marshal(sf)
	old := filepath.Join(dir, "state.json")
	if err := os.WriteFile(old, b, 0o644); err != nil {
		t.Fatal(err)
	}

	st := testStore(t, dir)
	if r, ok := st.Get("wp:x"); !ok || r.Notes != "look at ajax" {
		t.Fatalf("imported repo = %+v, %v", r, ok)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Error("state.json still in place after import")
	}
	if _, err := os.Stat(old + ".imported"); err != nil {
		t.Errorf("no backup kept: %v", err)
	}
	if id := st.AddRun(RunRecord{}); id != 8 {
		t.Errorf("next run id = %d, want 8", id)
	}
	st.Close()

	// a second start reads the database, not a state.json that reappeared
	os.WriteFile(old, []byte(`{"repos":{}}`), 0o644)
	st2 := testStore(t, dir)
	if _, ok := st2.Get("wp:x"); !ok {
		t.Error("repo lost on second open")
	}
	if _, err := os.Stat(old); err != nil {
		t.Error("state.json touched although the database already had data")
	}
}
