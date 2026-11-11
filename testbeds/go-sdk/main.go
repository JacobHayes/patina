// A Go guest instrumented with Patina's Go SDK (go/patina): an invariant, a
// coverage site satisfied on some seeds' draws, a point always reached, and a
// point never reached, all declared at package level; a fault site, a delay
// site and a knob; a setup boundary; a pass verdict; seeded entropy; and the
// run parameter `violate` (or, outside Patina, an argument) that breaks the
// invariant.
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
	dropDraw = patina.Buggify("go-sdk-drop-draw")
	stall    = patina.BuggifyDelay("go-sdk-stall")
	width    = patina.Knob("go-sdk-ledger-width", 8, 4, 16)
)

func main() {
	_, violate := patina.Param("violate")
	violate = violate || slices.Contains(os.Args[1:], "violate")
	patina.SetupComplete()
	patina.LifecycleEvent("go-sdk-workload")

	ledger := make([]uint64, width.Value())
	dropped := 0
	for i := range ledger {
		ledger[i] = patina.Rng() % 1000
		if dropDraw.FiresWithProb(0.5) {
			ledger[i] = 0
			dropped++
		}
		evenDraw.Check(ledger[i]%2 == 0)
	}
	stall.Delay()
	slices.Sort(ledger)
	if violate {
		ledger[0], ledger[len(ledger)-1] = ledger[len(ledger)-1], ledger[0]
	}
	held := sorted.Check(slices.IsSorted(ledger), "ledger=", ledger)
	settled.Mark()
	if len(ledger) == 0 {
		never.Mark()
	}

	if held {
		patina.Verdict(patina.Pass, "go-sdk-ledger-settled", fmt.Sprintf(`{"width":%d}`, len(ledger)))
	}
	fmt.Printf("GO_SDK_RESULT simulated=%t held=%t first=%d width=%d dropped=%d\n",
		patina.IsSimulated(), held, ledger[0], len(ledger), dropped)
}
