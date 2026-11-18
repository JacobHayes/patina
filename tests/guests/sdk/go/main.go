// The SDK test guest in Go: the script of guest.c (modes script [two], fail, unreach, coin,
// loop, marks).
package main

import (
	"crypto/rand"
	"fmt"
	"os"
	"strconv"

	"github.com/JacobHayes/patina/go/patina"
)

var (
	scriptStart = patina.Reachable("script-start")
	unreached   = patina.Sometimes("unreached")
	bounded     = patina.Always("bounded")
	halfWay     = patina.Sometimes("half-way")
	neverHolds  = patina.Sometimes("never-holds")
	pointA      = patina.Buggify("point-a")
	pointB      = patina.Buggify("point-b")
	knobA       = patina.Knob("knob-a", 7, 1, 100)
	delayA      = patina.BuggifyDelay("delay-a")
	beforeFail  = patina.Reachable("before-fail")
	mustHold    = patina.Always("must-hold")
	afterFail   = patina.Reachable("after-fail")
	neverHere   = patina.Unreachable("never-here")
	coin        = patina.Sometimes("coin")
	loopBounded = patina.Always("loop-bounded")
)

func script(two bool) {
	scriptStart.Mark()
	if len(os.Args) > 1000 {
		unreached.Check(true)
	}
	for i := 0; i < 1000; i++ {
		bounded.Check(i < 1000, "out of range")
		halfWay.Check(i == 500)
		neverHolds.Check(i > 5000)
	}
	bits := make([]byte, 20)
	for i := range bits {
		bits[i] = '0'
		if pointA.Fires() {
			bits[i] = '1'
		}
		if two {
			pointB.Fires()
		}
	}
	slept := 0
	k := knobA.Value()
	if delayA.DelayUpTo(1000000) {
		slept = 1
	}
	fmt.Printf("a=%s knob=%d delay=%d\n", bits, k, slept)
}

func main() {
	mode := "script"
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}
	switch mode {
	case "script":
		script(len(os.Args) > 2 && os.Args[2] == "two")
	case "fail":
		beforeFail.Mark()
		balance := -1
		mustHold.Check(balance >= 0, "balance ", balance)
		afterFail.Mark()
	case "unreach":
		neverHere.Reached("reached")
	case "coin":
		b := make([]byte, 1)
		if _, err := rand.Read(b); err != nil {
			os.Exit(2)
		}
		coin.Check(b[0]%2 == 0)
	case "loop":
		n := int64(10000000)
		if len(os.Args) > 2 {
			n, _ = strconv.ParseInt(os.Args[2], 10, 64)
		}
		sdk := len(os.Args) > 3 && os.Args[3] == "sdk"
		var acc uint64
		for i := int64(0); i < n; i++ {
			acc = acc*31 + uint64(i)
			if sdk {
				loopBounded.Check(acc != ^uint64(0), "saturated")
			}
		}
		fmt.Println(acc)
	case "marks":
		patina.Mark("ack 1")
		if err := os.WriteFile("marked", []byte("x"), 0o644); err != nil {
			os.Exit(2)
		}
		patina.Mark("ack 2")
	default:
		fmt.Fprintln(os.Stderr, "unknown mode", mode)
		os.Exit(2)
	}
}
