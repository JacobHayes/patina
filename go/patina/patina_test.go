package patina

import "testing"

// A label the shim would refuse fails at its declaration, in every build,
// instead of leaving a site that checks nothing.
func TestALabelThatIsNotUTF8IsRefusedAtDeclaration(t *testing.T) {
	for _, label := range []string{"", "ledger-\xff"} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("Always(%q) declared a site", label)
				}
			}()
			Always(label)
		}()
	}
}

// Outside Patina a site returns its condition and does nothing else.
func TestSitesAreInertOutsidePatina(t *testing.T) {
	if IsSimulated() {
		t.Fatal("simulated in a plain build")
	}
	if Always("inert-always").Check(false) {
		t.Fatal("Always.Check(false) returned true")
	}
	if !Sometimes("inert-sometimes").Check(true) {
		t.Fatal("Sometimes.Check(true) returned false")
	}
	Reachable("inert-reachable").Mark()
	if _, ok := Param("anything"); ok {
		t.Fatal("a parameter outside Patina")
	}
}

// formatted fails the test if a detail is ever formatted.
type formatted struct{ t *testing.T }

func (f formatted) String() string {
	f.t.Error("an inert check formatted its detail")
	return ""
}

// Outside Patina faults never fire, knobs keep their defaults, a failed
// check formats no detail.
func TestFaultsAreInertOutsidePatina(t *testing.T) {
	if Buggify("inert-fault").Fires() || Buggify("inert-fault-prob").FiresWithProb(1) {
		t.Fatal("a fault fired outside Patina")
	}
	if BuggifyDelay("inert-delay").Delay() {
		t.Fatal("a delay was injected outside Patina")
	}
	if got := Knob("inert-knob", 64, 1, 1024).Value(); got != 64 {
		t.Fatalf("Knob.Value() = %d, not its default", got)
	}
	Always("inert-always-detail").Check(false, formatted{t})
	Verdict(Violation, "inert-verdict", "")
	SetupComplete()
	LifecycleEvent("inert-event")
}
