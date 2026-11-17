//go:build !(linux && (amd64 || arm64))

// Package compute gives a Go program compute points under Patina (see compute.go). Patina
// runs Linux x86-64 and arm64 programs; elsewhere this package defines no hooks, so a build with
// -gcflags=all=-d=libfuzzer fails to link and a build without it is unchanged.
package compute
