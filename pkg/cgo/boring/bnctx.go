//go:build !purego && !nobignum

package boring

// #cgo CFLAGS: -I "${SRCDIR}/../../../thirdparty/boringssl/include"
// #include <openssl/bn.h>
import "C"
import "runtime"

type nativeBnCtx = *C.BN_CTX

type BigNumCtx struct {
	nativeBnCtx

	noCopy      noCopy
	copyChecker copyChecker
}

func NewBigNumCtx() *BigNumCtx {
	bnCtx := C.BN_CTX_new()
	if bnCtx == nil {
		panic("BN_CTX_new")
	}
	ctx := &BigNumCtx{
		nativeBnCtx: bnCtx,
	}
	runtime.SetFinalizer(ctx, func(ctx *BigNumCtx) {
		C.BN_CTX_free(ctx.nativeBnCtx)
		ctx.nativeBnCtx = nil
		runtime.KeepAlive(ctx)
	})

	ctx.copyChecker.check()
	return ctx
}
