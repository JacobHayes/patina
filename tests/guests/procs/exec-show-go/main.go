// Exec target in Go: same output as exec-show.c.
package main

import (
	"fmt"
	"os"
	"syscall"
)

func main() {
	exe, _ := os.Readlink("/proc/self/exe")
	fmt.Printf("exe=%s\n", exe)
	for i, a := range os.Args {
		fmt.Printf("argv[%d]=%s\n", i, a)
	}
	e, ok := os.LookupEnv("EXEC_SHOW_ENV")
	if !ok {
		e = "(unset)"
	}
	fmt.Printf("env=%s\n", e)
	fmt.Printf("fds=")
	for fd := 0; fd < 64; fd++ {
		if _, _, err := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFD, 0); err == 0 {
			fmt.Printf("%d,", fd)
		}
	}
	fmt.Printf("\n")
	_, _, err := syscall.Syscall(syscall.SYS_FCNTL, 3000, syscall.F_GETFD, 0)
	if err != 0 {
		fmt.Printf("hidden=-1,%s\n", "Bad file descriptor")
	} else {
		fmt.Printf("hidden=open\n")
	}
}
