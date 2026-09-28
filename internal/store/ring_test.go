package store

import "testing"

func mk(ts int64, vals map[string]float64) Frame {
	f := Frame{TS: ts, V: map[string]*Point{}}
	for k, v := range vals {
		f.V[k] = &Point{Rx: v, Tx: v / 2}
	}
	return f
}

func TestRingEviction(t *testing.T) {
	r := New(3)
	for i := 1; i <= 5; i++ {
		r.Push(mk(int64(i), map[string]float64{"a": float64(i)}))
	}
	if r.Len() != 3 {
		t.Fatalf("Len = %d, want 3", r.Len())
	}
	s := r.Snapshot(0)
	if s[0].TS != 3 || s[2].TS != 5 {
		t.Errorf("snapshot spans %d..%d, want 3..5", s[0].TS, s[2].TS)
	}
	last, ok := r.Last()
	if !ok || last.TS != 5 {
		t.Errorf("Last = %v %v", last.TS, ok)
	}
}

// Reconfiguration must not throw away the window for interfaces the operator
// left alone.
func TestRebuildKeepsSurvivingSeries(t *testing.T) {
	r := New(10)
	for i := 1; i <= 5; i++ {
		r.Push(mk(int64(i), map[string]float64{"keep": 10, "drop": 20}))
	}
	n := r.Rebuild(10, map[string]bool{"keep": true, "added": true})

	if n.Len() != 5 {
		t.Fatalf("rebuilt Len = %d, want 5", n.Len())
	}
	for _, f := range n.Snapshot(0) {
		if f.V["keep"] == nil {
			t.Error("surviving interface lost its history")
		}
		if _, ok := f.V["drop"]; ok {
			t.Error("removed interface should not be carried over")
		}
		if _, ok := f.V["added"]; ok {
			t.Error("newly added interface must not be invented history")
		}
	}
	if n.Snapshot(0)[0].TS != 1 {
		t.Error("rebuild should preserve the original timeline")
	}
}

func TestRebuildTruncatesToNewCapacity(t *testing.T) {
	r := New(10)
	for i := 1; i <= 10; i++ {
		r.Push(mk(int64(i), map[string]float64{"a": 1}))
	}
	n := r.Rebuild(4, map[string]bool{"a": true})
	if n.Len() != 4 {
		t.Fatalf("Len = %d, want 4", n.Len())
	}
	if got := n.Snapshot(0)[0].TS; got != 7 {
		t.Errorf("kept oldest TS %d, want the newest 4 starting at 7", got)
	}
}
