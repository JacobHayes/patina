// Go net: a listener and dialers in one process. Each of 16 goroutines dials,
// sends 50 requests and checks the echoes; the server runs a goroutine per connection.
// Also a deadline that expires, and a refused dial.
package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

func main() {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	must(err)
	addr := l.Addr().String()
	var served sync.WaitGroup
	var mu sync.Mutex
	lines := 0
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			served.Add(1)
			go func(c net.Conn) {
				defer served.Done()
				defer c.Close()
				r := bufio.NewReader(c)
				for {
					s, err := r.ReadString('\n')
					if err == io.EOF {
						return
					}
					must(err)
					mu.Lock()
					lines++
					mu.Unlock()
					_, err = c.Write([]byte(s))
					must(err)
				}
			}(c)
		}
	}()
	var wg sync.WaitGroup
	sums := make([]int, 16)
	for id := 0; id < 16; id++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			c, err := net.Dial("tcp", addr)
			must(err)
			r := bufio.NewReader(c)
			for i := 0; i < 50; i++ {
				msg := fmt.Sprintf("goroutine %02d message %03d\n", id, i)
				_, err := c.Write([]byte(msg))
				must(err)
				back, err := r.ReadString('\n')
				must(err)
				if back != msg {
					fail("echo mismatch")
				}
				for _, b := range []byte(back) {
					sums[id] += int(b)
				}
			}
			must(c.(*net.TCPConn).CloseWrite())
			if _, err := r.ReadByte(); err != io.EOF {
				fail("expected EOF")
			}
			c.Close()
		}(id)
	}
	wg.Wait()
	served.Wait()
	sum := 0
	for _, s := range sums {
		sum += s
	}
	// A read deadline on an idle connection expires in virtual time.
	c, err := net.Dial("tcp", addr)
	must(err)
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = c.Read(make([]byte, 1))
	var ne net.Error
	timedOut := errors.As(err, &ne) && ne.Timeout()
	c.Close()
	l.Close()
	_, err = net.Dial("tcp", addr)
	fmt.Printf("go-net lines %d checksum %d deadline %v redial refused %v\n", lines, sum, timedOut, err != nil)
}

func must(err error) {
	if err != nil {
		fail(err.Error())
	}
}

func fail(s string) {
	fmt.Println("FAIL", s)
	os.Exit(1)
}
