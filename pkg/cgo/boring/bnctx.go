//go:build !purego && !nobignum

package boring

// #include "openssl/bn.h"
import "C"
import (
	"github.com/bronlabs/bron-crypto/pkg/base/utils/nocopy"
	"runtime"
)

type nativeBnCtx = *C.BN_CTX

type BigNumCtx struct {
	nativeBnCtx

	noCopy      nocopy.NoCopy
	copyChecker nocopy.CopyChecker
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

	ctx.copyChecker.Check()
	return ctx
}
