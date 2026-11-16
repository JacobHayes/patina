// go-sweep: the smallest program found that stalls under patina at GOMAXPROCS >= 3. Four
// goroutines allocate and drop 1 KiB slices (so the heap is swept by both the allocating
// goroutines and the background sweeper), then one GC. No I/O.
package main

import (
	"fmt"
	"runtime"
	"sync"
)

func main() {
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var keep [][]byte
			for j := 0; j < 20000; j++ {
				keep = append(keep, make([]byte, 1024))
				if len(keep) > 256 {
					keep = keep[:0]
				}
			}
		}()
	}
	wg.Wait()
	runtime.GC()
	fmt.Println("gomaxprocs", runtime.GOMAXPROCS(0), "done")
}
