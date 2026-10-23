// A pure-Go guest: goroutines across threads, channels, timers, SHA-1 (which
// links Go's crypto build marker), a file round trip and fmt; and goroutines
// that compute without making a call while another waits on a timer, plus
// goroutines that allocate while the garbage collector sweeps beside them.
package main

import (
	"context"
	"crypto/sha1"
	"fmt"
	"os"
	"sync"
	"time"
)

// spin computes until ctx is done, never making a system call.
func spin(ctx context.Context, buf []byte) (rounds int) {
	for ctx.Err() == nil {
		for i := range buf {
			buf[i] = byte(i) ^ buf[(i+1)%len(buf)]
		}
		rounds++
	}
	return rounds
}

// compute: a goroutine computes until a timer cancels it, and the main
// goroutine spins on a word a timer's goroutine sets, in a loop that calls
// nothing. Both finish only if computing lets time pass and other goroutines
// run.
func compute() string {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	done := make(chan int)
	go func() { done <- spin(ctx, make([]byte, 4096)) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		return "hung"
	}
	var stop uint32
	time.AfterFunc(10*time.Millisecond, func() { stop = 1 })
	for stop == 0 {
	}
	return "cancelled"
}

// allocate: goroutines allocate and drop buffers, so the garbage collector
// runs and sweeps beside them.
func allocate() int {
	var wg sync.WaitGroup
	var mu sync.Mutex
	kept := make([][]byte, 0, 64)
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 2000 {
				b := make([]byte, 64<<10)
				b[i%len(b)] = byte(i)
				if i%7 == 0 {
					mu.Lock()
					kept = append(kept, b)
					if len(kept) == cap(kept) {
						kept = kept[:0]
					}
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	return 4 * 2000
}

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

	computed := compute()
	allocated := allocate()

	fmt.Printf("GO_GUEST_RESULT sha=%x total=%d data=%q mode=%v slept=%t compute=%s allocated=%d\n",
		sums[7][:4], total, data, info.Mode(), time.Since(start) >= 7*time.Millisecond,
		computed, allocated)
	// Virtual time: the same at a seed, so the repeat and replay legs compare it.
	fmt.Printf("GO_GUEST_CLOCK elapsed_ns=%d\n", time.Since(start).Nanoseconds())
	// The guest's stderr, so the repeat and replay legs compare that stream too.
	fmt.Fprintf(os.Stderr, "GO_GUEST_STDERR sha=%x\n", sums[0][:4])
}
