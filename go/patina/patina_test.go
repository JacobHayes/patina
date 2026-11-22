package patina

import "testing"

// A label that cannot cross the wire fails at its declaration, in every build.
func TestABadLabelIsRefusedAtDeclaration(t *testing.T) {
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

// formatted fails the test if a detail is ever formatted.
type formatted struct{ t *testing.T }

func (f formatted) String() string {
	f.t.Error("an inert check formatted its detail")
	return ""
}

// Outside Patina a site returns its condition, faults never fire, knobs keep their defaults.
func TestSitesAreInertOutsidePatina(t *testing.T) {
	if IsSimulated() {
		t.Fatal("simulated outside Patina")
	}
	if Always("inert-always").Check(false, formatted{t}) {
		t.Fatal("Always.Check(false) returned true")
	}
	if !Sometimes("inert-sometimes").Check(true) {
		t.Fatal("Sometimes.Check(true) returned false")
	}
	Reachable("inert-reachable").Hit()
	if Buggify("inert-fault").Fires() {
		t.Fatal("a fault fired outside Patina")
	}
	if Delay("inert-delay").Delay(0) {
		t.Fatal("a delay was injected outside Patina")
	}
	if got := Knob("inert-knob", 64, 1, 1024).Value(); got != 64 {
		t.Fatalf("Knob.Value() = %d, not its default", got)
	}
	Mark("inert-mark")
}
