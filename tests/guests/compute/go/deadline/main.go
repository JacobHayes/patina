// go-deadline [MAX [MS]]: a CPU-bound loop under context.WithTimeout(MS ms, default 50). The
// loop does integer work and polls ctx.Err() every 1024 iterations, with no system call in
// between; it ends when the context is done or after MAX iterations (default 2^31). Prints the iterations, the
// elapsed time (virtual under Patina) and whether the deadline ended it; exit status 1 if it
// did not. Built with compute points (go-deadline) and stock (go-deadline-stock).
package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	_ "github.com/JacobHayes/patina/go/patina/compute"
)

var table [256]uint64

func main() {
	max, ms := uint64(1)<<31, uint64(50)
	for k, p := range []*uint64{&max, &ms} {
		if len(os.Args) > k+1 {
			n, err := strconv.ParseUint(os.Args[k+1], 10, 64)
			if err != nil {
				fmt.Fprintln(os.Stderr, "usage: go-deadline [MAX [MS]]")
				os.Exit(2)
			}
			*p = n
		}
	}
	for i := range table {
		table[i] = uint64(i + len(os.Args))
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(ms)*time.Millisecond)
	defer cancel()
	start := time.Now()
	var i, sum uint64
	for i = 0; i < max; i++ {
		sum += table[i&255] ^ i
		if i&1023 == 0 && ctx.Err() != nil {
			break
		}
	}
	el := time.Since(start)
	how := "deadline"
	if ctx.Err() == nil {
		how = "no-deadline"
	}
	fmt.Printf("iterations=%d sum=%d elapsed_ns=%d %s\n", i, sum, el.Nanoseconds(), how)
	if how != "deadline" {
		os.Exit(1)
	}
}
