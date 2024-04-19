//go:build !purego && !nobignum

package boring

// #cgo CFLAGS: -I "${SRCDIR}/../../../thirdparty/boringssl" -I "${SRCDIR}/../../../thirdparty/boringssl/include"
// #cgo LDFLAGS: -L"${SRCDIR}/../../../thirdparty/boringssl/build/crypto" -lcrypto
// #include "crypto/fipsmodule/bn/internal.h"
// #include <openssl/err.h>
//
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
	bn.copyChecker.check()
	b.copyChecker.check()
	bnCtx.copyChecker.check()

	ret := C.BN_jacobi(&bn.nativeBigNum, &b.nativeBigNum, bnCtx.nativeBnCtx)
	if ret == -2 {
		return 0, lastError()
	}

	runtime.KeepAlive(bn)
	runtime.KeepAlive(b)
	runtime.KeepAlive(bnCtx)
	return int(ret), nil
}

func lastError() error {
	errno := C.ERR_get_error()
	if errno == 0 {
		panic("ERR_get_error")
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
