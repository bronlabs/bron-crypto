package boring

// #cgo CFLAGS: -I "${SRCDIR}/../../../../../boringssl"
// #cgo LDFLAGS: -L"${SRCDIR}/../../../../../boringssl/build/crypto" -lcrypto
// #include "crypto/fipsmodule/bn/internal.h"
//
// OPENSSL_EXPORT int BN_jacobi(const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
//
// int BN_jacobi(const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx) {
//     return bn_jacobi(a, b, ctx);
// }
import "C"
import "runtime"

func (bn *BigNum) Jacobi(b *BigNum, bnCtx *BigNumCtx) int {
	bn.copyChecker.check()
	b.copyChecker.check()
	bnCtx.copyChecker.check()

	ret := C.BN_jacobi(&bn.nativeBigNum, &b.nativeBigNum, bnCtx.nativeBnCtx) //nolint:gocritic // false positive
	if ret == -2 {
		panic("BN_jacobi")
	}

	runtime.KeepAlive(bn)
	runtime.KeepAlive(b)
	runtime.KeepAlive(bnCtx)
	return int(ret)
}
