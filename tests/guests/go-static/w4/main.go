// W4 go-static: a stock static Go program (GOMAXPROCS left at its default) that uses
// goroutines, channels, a contended mutex, time.After and a ticker, os/exec of coreutils,
// file writes from several goroutines and, in mode "all", an HTTP server and 16 concurrent
// clients over loopback in the same process.
//
//	go-static local   everything except the network part
//	go-static net     only the network part
//	go-static all     both (the full W4 row)
//
// Lines that depend on the schedule start with "~ " (their content differs between seeds and
// is identical for one seed). Errors from file operations are printed and counted, never
// fatal: under fs-error-permille the program reports them and finishes. The last line is
// "done".
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

func work(id, n int) uint64 {
	h := uint64(id)*0x9e3779b97f4a7c15 + 1
	for i := 0; i < n; i++ {
		h ^= h << 13
		h ^= h >> 7
		h ^= h << 17
	}
	return h
}

func goroutines() {
	type res struct {
		id int
		h  uint64
	}
	ch := make(chan res)
	var mu sync.Mutex
	shared := 0
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for k := 0; k < 50; k++ {
				mu.Lock()
				shared++
				mu.Unlock()
				if k%10 == 0 {
					time.Sleep(time.Millisecond)
				}
			}
			ch <- res{id, work(id, 20000)}
		}(i)
	}
	go func() { wg.Wait(); close(ch) }()
	var order []string
	var sum uint64
	for r := range ch {
		order = append(order, fmt.Sprint(r.id))
		sum += r.h
	}
	fmt.Printf("goroutines: 16 results, sum %x, shared %d\n", sum, shared)
	fmt.Printf("~ completion order %s\n", strings.Join(order, " "))
}

// alloc: 8 goroutines allocate and drop small objects while main forces collections, so
// the garbage collector stops the world and preempts running goroutines (Go's SIGURG).
func alloc() {
	var wg sync.WaitGroup
	sums := make([]int, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var keep [][]byte
			for k := 0; k < 20000; k++ {
				b := make([]byte, 64+k%512)
				b[0] = byte(k)
				keep = append(keep, b)
				if len(keep) > 256 {
					for _, x := range keep {
						sums[i] += int(x[0])
					}
					keep = keep[:0]
				}
			}
		}(i)
	}
	for k := 0; k < 3; k++ {
		runtime.GC()
	}
	wg.Wait()
	t := 0
	for _, s := range sums {
		t += s
	}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	fmt.Printf("alloc: checksum %d, gc cycles >= 3: %v\n", t, ms.NumGC >= 3)
}

func timers() {
	never := make(chan int)
	t0 := time.Now()
	select {
	case <-never:
		fmt.Println("time.After: wrong branch")
	case <-time.After(2 * time.Second):
		fmt.Println("time.After: 2s timeout fired")
	}
	el := time.Since(t0)
	fmt.Printf("time.After: elapsed >= 2s: %v\n", el >= 2*time.Second)
	tk := time.NewTicker(100 * time.Millisecond)
	n := 0
	for range tk.C {
		n++
		if n == 5 {
			break
		}
	}
	tk.Stop()
	fmt.Printf("ticker: %d ticks\n", n)
	fmt.Printf("~ now %s\n", time.Now().UTC().Format(time.RFC3339Nano))
}

func execs() {
	cmd := exec.Command("sort", "-n")
	cmd.Stdin = strings.NewReader("30\n4\n200\n17\n")
	out, err := cmd.Output()
	fmt.Printf("exec sort: %q err=%v\n", string(out), err)
	err = exec.Command("sh", "-c", "exit 3").Run()
	if ee, ok := err.(*exec.ExitError); ok {
		fmt.Printf("exec sh exit: %d\n", ee.ExitCode())
	} else {
		fmt.Printf("exec sh exit: unexpected %v\n", err)
	}
	// Several children at once, from several goroutines.
	var wg sync.WaitGroup
	outs := make([]string, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			o, err := exec.Command("seq", "-s", ",", "1", fmt.Sprint(i+2)).Output()
			outs[i] = strings.TrimSpace(string(o))
			if err != nil {
				outs[i] = "err:" + err.Error()
			}
		}(i)
	}
	wg.Wait()
	fmt.Printf("exec seq x4: %s\n", strings.Join(outs, " "))
}

func files() {
	// Under the working directory (/work under patina, where file faults apply).
	dir, err := os.MkdirTemp(".", "w4-")
	if err != nil {
		fmt.Println("files: mkdtemp error:", err)
		return
	}
	fmt.Printf("~ tempdir %s\n", dir)
	var mu sync.Mutex
	var errs []string
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			fail := func(what string, err error) {
				mu.Lock()
				errs = append(errs, fmt.Sprintf("%d %s: %v", i, what, err))
				mu.Unlock()
			}
			tmp := filepath.Join(dir, fmt.Sprintf("f%d.tmp", i))
			f, err := os.Create(tmp)
			if err != nil {
				fail("create", err)
				return
			}
			for k := 0; k < 16; k++ {
				if _, err := fmt.Fprintf(f, "file %d line %d\n", i, k); err != nil {
					fail("write", err)
					f.Close()
					return
				}
			}
			if err := f.Sync(); err != nil {
				fail("fsync", err)
			}
			if err := f.Close(); err != nil {
				fail("close", err)
			}
			if err := os.Rename(tmp, filepath.Join(dir, fmt.Sprintf("f%d", i))); err != nil {
				fail("rename", err)
			}
		}(i)
	}
	wg.Wait()
	h := sha256.New()
	ents, err := os.ReadDir(dir)
	if err != nil {
		fmt.Println("files: readdir error:", err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	for _, n := range names {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			errs = append(errs, fmt.Sprintf("read %s: %v", n, err))
			continue
		}
		h.Write([]byte(n))
		h.Write(b)
	}
	sort.Strings(errs)
	for _, e := range errs {
		fmt.Println("file error:", e)
	}
	fmt.Printf("files: %d names, %d errors, digest %s\n", len(names), len(errs), hex.EncodeToString(h.Sum(nil))[:16])
	if err := os.RemoveAll(dir); err != nil {
		fmt.Println("file error: removeall:", err)
	}
}

func network() {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Println("net: listen error:", err)
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/echo/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello %s", strings.TrimPrefix(r.URL.Path, "/echo/"))
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	url := "http://" + ln.Addr().String() + "/echo/"
	var wg sync.WaitGroup
	got := make([]string, 16)
	cl := &http.Client{Timeout: 5 * time.Second}
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp, err := cl.Get(fmt.Sprintf("%s%d", url, i))
			if err != nil {
				got[i] = "err:" + err.Error()
				return
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			got[i] = string(b)
		}(i)
	}
	wg.Wait()
	ok := 0
	for i, g := range got {
		if g == fmt.Sprintf("hello %d", i) {
			ok++
		} else {
			fmt.Printf("net: request %d: %s\n", i, g)
		}
	}
	srv.Close()
	fmt.Printf("net: %d of 16 responses correct\n", ok)
}

func main() {
	mode := "all"
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}
	fmt.Printf("gomaxprocs %d numcpu %d\n", runtime.GOMAXPROCS(0), runtime.NumCPU())
	if mode != "net" {
		goroutines()
		alloc()
		timers()
		execs()
		files()
	}
	if mode != "local" {
		network()
	}
	fmt.Println("done")
}
