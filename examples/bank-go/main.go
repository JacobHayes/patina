// A bank server and its client in one program, over HTTP on localhost. The client deposits 1,
// twenty times, retrying a deposit whose request failed. The balance must equal the deposits
// the client saw succeed.
//
// The bug: when a connection is reset after the server applied a deposit, the retry applies it
// again. `bank fixed` sends a request id, and the server applies each id once.
package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"

	"github.com/JacobHayes/patina/go/patina"
)

var balanceMatches = patina.Always("balance-matches-deposits")

func main() {
	fixed := len(os.Args) > 1 && os.Args[1] == "fixed"
	var mu sync.Mutex
	balance, seen := 0, map[string]bool{}
	http.HandleFunc("/deposit", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if id := r.Header.Get("Request-Id"); !fixed || !seen[id] {
			seen[id] = true
			balance++
		}
		fmt.Fprintln(w, balance)
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	go http.Serve(ln, nil)

	url := "http://" + ln.Addr().String() + "/deposit"
	deposits := 0
	for i := 0; i < 20; i++ {
		for { // retry until the deposit succeeds
			req, _ := http.NewRequest("POST", url, nil)
			req.Header.Set("Request-Id", fmt.Sprint(i))
			req.Close = true // a new connection per request
			if resp, err := http.DefaultClient.Do(req); err == nil {
				resp.Body.Close()
				break
			}
		}
		deposits++
	}
	mu.Lock()
	defer mu.Unlock()
	balanceMatches.Check(balance == deposits, "balance ", balance, ", deposits ", deposits)
	fmt.Println("balance", balance, "after", deposits, "deposits")
}
