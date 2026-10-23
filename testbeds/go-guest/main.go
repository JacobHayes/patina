// A pure-Go guest: goroutines across threads, channels, timers, SHA-1 (which
// links Go's crypto build marker), a file round trip and fmt.
package main

import (
	"crypto/sha1"
	"fmt"
	"os"
	"sync"
	"time"
)

func fail(err error) {
	fmt.Fprintln(os.Stderr, "go-guest:", err)
	os.Exit(1)
}

func main() {
	start := time.Now()

	// Goroutines that block, so the runtime starts more threads to run them.
	var wg sync.WaitGroup
	sums := make([][20]byte, 8)
	for i := range sums {
		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(time.Duration(i) * time.Millisecond)
			sums[i] = sha1.Sum(fmt.Appendf(nil, "leg %d", i))
		}()
	}
	wg.Wait()

	ch := make(chan int)
	go func() {
		for i := range 100 {
			ch <- i
		}
		close(ch)
	}()
	total := 0
	for v := range ch {
		total += v
	}

	path := "/tmp/go-guest.txt"
	if err := os.WriteFile(path, []byte("hello from go\n"), 0o640); err != nil {
		fail(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		fail(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		fail(err)
	}

	fmt.Printf("GO_GUEST_RESULT sha=%x total=%d data=%q mode=%v slept=%t\n",
		sums[7][:4], total, data, info.Mode(), time.Since(start) >= 7*time.Millisecond)
	// Virtual time: the same at a seed, so the repeat and replay legs compare it.
	fmt.Printf("GO_GUEST_CLOCK elapsed_ns=%d\n", time.Since(start).Nanoseconds())
	// The guest's stderr, so the repeat and replay legs compare that stream too.
	fmt.Fprintf(os.Stderr, "GO_GUEST_STDERR sha=%x\n", sums[0][:4])
}
