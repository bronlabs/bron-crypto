package boring

import (
	"sync"
	"sync/atomic"
	"unsafe"
)

// copyChecker holds back pointer to itself to detect object copying.
type copyChecker uintptr

func (c *copyChecker) check() {
	// Check if c has been copied in three steps:
	// 1. The first comparison is the fast-path. If c has been initialised and not copied, this will return immediately. Otherwise, c is either not initialised, or has been copied.
	// 2. Ensure c is initialised. If the CAS succeeds, we're done. If it fails, c was either initialised concurrently and we simply lost the race, or c has been copied.
	// 3. Do step 1 again. Now that c is definitely initialised, if this fails, c was copied.
	if uintptr(*c) != uintptr(unsafe.Pointer(c)) &&
		!atomic.CompareAndSwapUintptr((*uintptr)(c), 0, uintptr(unsafe.Pointer(c))) &&
		uintptr(*c) != uintptr(unsafe.Pointer(c)) {

		panic("object is copied")
	}
}

// noCopy may be added to structs which must not be copied
// after the first use.
//
// See https://golang.org/issues/8005#issuecomment-190753527
// for details.
//
// Note that it must not be embedded, due to the Lock and Unlock methods.
type noCopy struct{}

var _ sync.Locker = (*noCopy)(nil)

// Lock is a no-op used by -copylocks checker from `go vet`.
func (*noCopy) Lock()   {}
func (*noCopy) Unlock() {}
