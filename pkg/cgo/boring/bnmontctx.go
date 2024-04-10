//go:build !nobignum

package boring

// #cgo CFLAGS: -I "${SRCDIR}/../../../thirdparty/boringssl/include"
// #include <openssl/bn.h>
import "C"
import "runtime"

type nativeBnMontCtx = *C.BN_MONT_CTX

type BigNumMontCtx struct {
	nativeBnMontCtx

	noCopy      noCopy
	copyChecker copyChecker
}

func NewBigNumMontCtx(m *BigNum, bigNumCtx *BigNumCtx) (*BigNumMontCtx, error) {
	m.copyChecker.check()
	bigNumCtx.copyChecker.check()

	nativeCtx := C.BN_MONT_CTX_new_consttime(&m.nativeBigNum, bigNumCtx.nativeBnCtx)
	if nativeCtx == nil {
		return nil, lastError()
	}
	ctx := &BigNumMontCtx{
		nativeBnMontCtx: nativeCtx,
	}

	runtime.SetFinalizer(ctx, func(montCtx *BigNumMontCtx) {
		C.BN_MONT_CTX_free(montCtx.nativeBnMontCtx)
		montCtx.nativeBnMontCtx = nil
		runtime.KeepAlive(montCtx)
	})

	ctx.copyChecker.check()
	runtime.KeepAlive(m)
	runtime.KeepAlive(bigNumCtx)
	return ctx, nil
}
