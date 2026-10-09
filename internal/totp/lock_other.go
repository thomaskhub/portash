//go:build !unix

package totp

import (
	"os"
	"sync"
)

// The servers that check codes run on Linux; elsewhere one process at a time
// is enough.
var mu sync.Mutex

func lockFile(*os.File) (func(), error) {
	mu.Lock()
	return mu.Unlock, nil
}

const noFollow = 0
