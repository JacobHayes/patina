# Go SDK

`github.com/JacobHayes/patina/go/patina`: invariants, coverage sites, fault points, knobs and
marks for a Go program run under Patina. Pure Go over one reserved system call: no cgo, no
build tag, inert (a load and a branch per call) outside Patina. See the package documentation.

`github.com/JacobHayes/patina/go/patina/compute`: compute points (a scheduling point at every
integer and string comparison) for a program built with `-gcflags=all=-d=libfuzzer`, by one
blank import. See its package documentation.
