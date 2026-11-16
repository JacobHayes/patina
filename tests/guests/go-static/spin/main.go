// go-spin: one goroutine runs a pure compute loop (no syscall, no allocation) for about
// 2 s of native time; four goroutines wait on its result through a channel and main waits
// on them with a 60 s time.After guard. Under patina the spinner holds the turn without
// trapping until it finishes (or until stall-ms ends the run as `stall`).
//
//	go-spin [ITERATIONS]   default 2000000000 (about 2 s on the measuring host)
package main

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

func spin(n uint64) uint64 {
	h := uint64(88172645463325252)
	for i := uint64(0); i < n; i++ {
		h ^= h << 13
		h ^= h >> 7
		h ^= h << 17
	}
	return h
}

func main() {
	n := uint64(2_000_000_000)
	if len(os.Args) > 1 {
		v, err := strconv.ParseUint(os.Args[1], 10, 64)
		if err != nil {
			fmt.Println("bad iteration count:", err)
			os.Exit(2)
		}
		n = v
	}
	res := make(chan uint64)
	done := make(chan string)
	for i := 0; i < 4; i++ {
		go func(i int) {
			v := <-res
			done <- fmt.Sprintf("waiter %d got %x", i, v)
		}(i)
	}
	go func() {
		v := spin(n)
		for i := 0; i < 4; i++ {
			res <- v
		}
	}()
	got := 0
	guard := time.After(60 * time.Second)
	for got < 4 {
		select {
		case <-done:
			got++
		case <-guard:
			fmt.Println("guard fired after 60 virtual seconds, waiters done:", got)
			os.Exit(1)
		}
	}
	fmt.Println("spin result delivered to 4 waiters")
}
