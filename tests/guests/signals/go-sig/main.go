// signals item 9: a goroutine in a for {} loop that calls a function making a syscall,
// a goroutine making a syscall every 10 ms (a raw nanosleep, in virtual time),
// signal.Notify(SIGUSR1) and syscall.Kill(self), with one P. The ticker and main only
// run if the spinner is preempted: Go's sysmon sends SIGURG through tgkill and the
// runtime delivers it at the spinner's next trap, through a frame Go inspects and edits.
package main

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"
)

var spins, ticks uint64

//go:noinline
func work(n uint64) uint64 {
	if n%1000 == 0 {
		syscall.Getpid()
	}
	return n + 1
}

func sleep(ns int64) {
	ts := syscall.NsecToTimespec(ns)
	syscall.Nanosleep(&ts, nil)
}

func main() {
	runtime.GOMAXPROCS(1)
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGUSR1)
	go func() {
		for {
			spins = work(spins)
		}
	}()
	go func() {
		for {
			sleep(10_000_000)
			ticks++
		}
	}()
	for ticks < 5 {
		sleep(10_000_000)
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGUSR1); err != nil {
		fmt.Println("kill:", err)
		os.Exit(1)
	}
	s := <-c
	fmt.Println("notified", s == syscall.SIGUSR1, "ticks>=5", ticks >= 5, "spun", spins > 0)
}
