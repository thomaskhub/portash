package main

import (
	"io"
	"os"
	"testing"
)

// capture runs f and returns what it printed on stdout.
func capture(t *testing.T, f func() error) (string, error) {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	runErr := f()
	w.Close()
	os.Stdout = old
	out, _ := io.ReadAll(r)
	return string(out), runErr
}
