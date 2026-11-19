// The rewriter's differential guest in Go: goroutines over channels, a mutex, sync/atomic, maps
// reported in key order, sort and strconv. Prints the same lines on every run.
package main

import (
	"fmt"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
)

func main() {
	var counter atomic.Int64
	var mu sync.Mutex
	locked := 0
	m := map[string]int{}
	ch := make(chan int, 16)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 20000; i++ {
				counter.Add(int64(i % 3))
				if i%500 == 0 {
					mu.Lock()
					locked += g
					m["k"+strconv.Itoa(i%17)] += i
					mu.Unlock()
					ch <- i
				}
			}
		}(g)
	}
	go func() { wg.Wait(); close(ch) }()
	sum := 0
	for v := range ch {
		sum += v
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	v := make([]int, 50000)
	for i := range v {
		v[i] = (i * 7919) % 10007
	}
	sort.Ints(v)
	fmt.Println("counter", counter.Load(), "locked", locked, "sum", sum)
	fmt.Println("keys", len(keys), keys[0], m[keys[0]], "v", v[0], v[len(v)-1])
}
