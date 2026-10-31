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
