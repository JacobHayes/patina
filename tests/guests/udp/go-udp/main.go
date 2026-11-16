// Go net over UDP: a ListenPacket echo server and DialUDP clients that retry on a read
// deadline; a dial to a port nobody holds (connection refused on read); IPv6 loopback.
// `go-udp dns`: net.LookupHost of localhost and of an unknown name.
package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "dns" {
		for _, n := range []string{"localhost", "unknown.example"} {
			a, err := net.LookupHost(n)
			var de *net.DNSError
			notFound := errors.As(err, &de) && de.IsNotFound
			fmt.Printf("%s: %v not-found %v (%v)\n", n, a, notFound, err)
		}
		return
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	must(err)
	go func() {
		b := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(b)
			if err != nil {
				return
			}
			pc.WriteTo(b[:n], from)
		}
	}()
	srv := pc.LocalAddr().(*net.UDPAddr)
	var wg sync.WaitGroup
	var mu sync.Mutex
	answers, resends := 0, 0
	for c := 0; c < 4; c++ {
		wg.Add(1)
		go func(c int) {
			defer wg.Done()
			conn, err := net.DialUDP("udp", nil, srv)
			must(err)
			defer conn.Close()
			b := make([]byte, 64)
			for k := 0; k < 20; k++ {
				msg := fmt.Sprintf("c%d m%02d", c, k)
				for {
					_, err := conn.Write([]byte(msg))
					must(err)
					conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
					n, err := conn.Read(b)
					if errors.Is(err, os.ErrDeadlineExceeded) {
						mu.Lock()
						resends++
						mu.Unlock()
						continue
					}
					must(err)
					if string(b[:n]) == msg {
						break
					}
				}
				mu.Lock()
				answers++
				mu.Unlock()
			}
		}(c)
	}
	wg.Wait()
	// A connected socket to a port nobody holds: the read reports connection refused.
	dead, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9})
	must(err)
	dead.Write([]byte("x"))
	dead.SetReadDeadline(time.Now().Add(time.Second))
	_, err = dead.Read(make([]byte, 8))
	refused := errors.Is(err, syscall.ECONNREFUSED)
	// IPv6 loopback.
	p6, err := net.ListenPacket("udp6", "[::1]:0")
	must(err)
	c6, err := net.DialUDP("udp6", nil, p6.LocalAddr().(*net.UDPAddr))
	must(err)
	c6.Write([]byte("six"))
	b := make([]byte, 8)
	n, from, err := p6.ReadFrom(b)
	must(err)
	fmt.Printf("go udp: answers %d resends %d refused %v v6 %s from %s\n", answers, resends, refused, b[:n], from.(*net.UDPAddr).IP)
	if answers != 80 || !refused || string(b[:n]) != "six" {
		os.Exit(1)
	}
}

func must(err error) {
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}
}
