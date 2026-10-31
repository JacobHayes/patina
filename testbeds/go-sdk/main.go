// A Go guest instrumented with Patina's Go SDK (go/patina): an invariant, a
// coverage site satisfied on some seeds' draws, a point always reached, and a
// point never reached, all declared at package level; seeded entropy; and a
// run parameter (or, outside Patina, an argument) that breaks the invariant.
package main

import (
	"fmt"
	"os"
	"slices"

	"github.com/JacobHayes/patina/go/patina"
)

var (
	sorted   = patina.Always("go-sdk-ledger-sorted")
	evenDraw = patina.Sometimes("go-sdk-even-draw")
	settled  = patina.Reachable("go-sdk-settled")
	never    = patina.Reachable("go-sdk-never-reached")
)

func main() {
	_, violate := patina.Param("violate")
	violate = violate || slices.Contains(os.Args[1:], "violate")

	ledger := make([]uint64, 8)
	for i := range ledger {
		ledger[i] = patina.Rng() % 1000
		evenDraw.Check(ledger[i]%2 == 0)
	}
	slices.Sort(ledger)
	if violate {
		ledger[0], ledger[len(ledger)-1] = ledger[len(ledger)-1], ledger[0]
	}
	held := sorted.Check(slices.IsSorted(ledger))
	settled.Mark()
	if len(ledger) == 0 {
		never.Mark()
	}
	fmt.Printf("GO_SDK_RESULT simulated=%t held=%t first=%d\n", patina.IsSimulated(), held, ledger[0])
}
