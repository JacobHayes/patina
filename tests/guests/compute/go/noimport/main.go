// noimport: a program built with -gcflags=all=-d=libfuzzer that does not import the hook
// package. It must not link (build.sh keeps the error in go-noimport.err).
package main

import (
	"fmt"
	"os"
)

func main() { fmt.Println(len(os.Args) > 1) }
