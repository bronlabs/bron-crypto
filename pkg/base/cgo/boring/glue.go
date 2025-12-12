//go:build !purego && !nobignum

package boring

// #include "openssl/bn.h"
// #include "openssl/err.h"
//
// extern int bn_jacobi(const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
// OPENSSL_EXPORT int BN_jacobi(const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
//
// int BN_jacobi(const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx) {
//     return bn_jacobi(a, b, ctx);
// }
import (
	"C"
)

import (
	"bytes"
	"errors"
	"runtime"
	"unsafe"
)

func (bn *BigNum) Jacobi(b *BigNum, bnCtx *BigNumCtx) (int, error) {
	bn.copyChecker.Check()
	b.copyChecker.Check()
	bnCtx.copyChecker.Check()

	lockOSThread()
	ret := C.BN_jacobi(&bn.nativeBigNum, &b.nativeBigNum, bnCtx.nativeBnCtx)
	if ret == -2 {
		err := lastError()
		unlockOSThread()
		return 0, err
	}
	unlockOSThread()

	runtime.KeepAlive(bn)
	runtime.KeepAlive(b)
	runtime.KeepAlive(bnCtx)
	return int(ret), nil
}

// lastError retrieves the most recent error from BoringSSL's thread-local error queue.
// IMPORTANT: This must be called on the same OS thread as the CGO call that failed.
// Use lockOSThread/unlockOSThread around CGO calls that may fail to ensure thread affinity.
func lastError() error {
	errno := C.ERR_get_error()
	if errno == 0 {
		// No error on this thread's queue - this can happen if the goroutine
		// migrated to a different OS thread between the CGO call and this call.
		// Return a generic error instead of panicking.
		return errors.New("boringssl: operation failed (error queue empty)")
	}

	var errBytes [128]byte
	ret := C.ERR_error_string_n(errno, (*C.char)(unsafe.Pointer(&errBytes[0])), C.size_t(len(errBytes)))
	if ret == nil {
		panic("ERR_error_string_n")
	}

	n := bytes.IndexByte(errBytes[:], 0)
	errString := string(errBytes[:n])
	err := errors.New(errString) //nolint:goerr113 // dynamic error from native

	return err //nolint:wrapcheck // false positive
}

// lockOSThread pins the current goroutine to its OS thread.
// This MUST be called before any CGO operation that may fail and require error retrieval.
// Call unlockOSThread when done with the CGO operation and error handling.
func lockOSThread() {
	runtime.LockOSThread()
}

// unlockOSThread unpins the current goroutine from its OS thread.
// This should be called after CGO operations and error handling are complete.
func unlockOSThread() {
	runtime.UnlockOSThread()
}
