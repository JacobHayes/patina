// go-race: syscall-free races in Go, built with compute points (the hook package and
// -gcflags=all=-d=libfuzzer).
//
//	go-race          16 rounds: in each, two goroutines meet at a spin barrier, then each
//	                 withdraws 100 from that round's balance of 100 if `balance.Load() >= 100`
//	                 holds, with `balance.Add(-100)`: no system call between the check and the
//	                 act. Prints the rounds in which both withdrew; "DOUBLE-SPEND" and exit
//	                 status 1 if there was one.
//	go-race boolspin a goroutine spins on `for !flag.Load() {}` (an atomic.Bool) until main sets
//	                 it after some work; prints "boolspin ok".
package main

import (
	"fmt"
	"os"
	"runtime"
	"sync"
	"sync/atomic"

	_ "github.com/JacobHayes/patina/go/patina/compute"
)

const rounds = 16

var (
	balance   [rounds]atomic.Int64
	withdrawn [rounds]atomic.Int64
	arrived   atomic.Int32
	flag      atomic.Bool
	sink      atomic.Int64
)

func withdraw(wg *sync.WaitGroup) {
	defer wg.Done()
	for r := range int32(rounds) {
		arrived.Add(1)
		for arrived.Load() < 2*(r+1) {
		}
		if balance[r].Load() >= 100 {
			balance[r].Add(-100)
			withdrawn[r].Add(100)
		}
	}
}

func race() int {
	for r := range balance {
		balance[r].Store(100)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go withdraw(&wg)
	go withdraw(&wg)
	wg.Wait()
	var double []int
	for r := range withdrawn {
		if withdrawn[r].Load() > 100 {
			double = append(double, r)
		}
	}
	if len(double) > 0 {
		fmt.Printf("rounds=%d double-spent in rounds %v DOUBLE-SPEND\n", rounds, double)
		return 1
	}
	fmt.Printf("rounds=%d ok\n", rounds)
	return 0
}

func boolspin() int {
	done := make(chan struct{})
	go func() {
		for !flag.Load() {
		}
		close(done)
	}()
	runtime.Gosched()
	s := int64(0)
	for i := int64(0); i < 100000; i++ {
		s += i & 7
	}
	sink.Store(s)
	flag.Store(true)
	<-done
	fmt.Println("boolspin ok")
	return 0
}

func main() {
	mode := "race"
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}
	switch mode {
	case "race":
		os.Exit(race())
	case "boolspin":
		os.Exit(boolspin())
	default:
		fmt.Fprintln(os.Stderr, "usage: go-race [race|boolspin]")
		os.Exit(2)
	}
}
