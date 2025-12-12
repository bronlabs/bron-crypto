//go:build !purego && !nobignum

package boring

// #include "openssl/bn.h"
import "C"
import (
	"runtime"

	"github.com/bronlabs/bron-crypto/pkg/base/utils/nocopy"
)

type nativeBnMontCtx = *C.BN_MONT_CTX

type BigNumMontCtx struct {
	nativeBnMontCtx

	noCopy      nocopy.NoCopy
	copyChecker nocopy.CopyChecker
}

func NewBigNumMontCtx(m *BigNum, bigNumCtx *BigNumCtx) (*BigNumMontCtx, error) {
	m.copyChecker.Check()
	bigNumCtx.copyChecker.Check()

	lockOSThread()
	nativeCtx := C.BN_MONT_CTX_new_consttime(&m.nativeBigNum, bigNumCtx.nativeBnCtx)
	if nativeCtx == nil {
		err := lastError()
		unlockOSThread()
		return nil, err
	}
	unlockOSThread()

	ctx := &BigNumMontCtx{
		nativeBnMontCtx: nativeCtx,
	}

	runtime.SetFinalizer(ctx, func(montCtx *BigNumMontCtx) {
		C.BN_MONT_CTX_free(montCtx.nativeBnMontCtx)
		montCtx.nativeBnMontCtx = nil
		runtime.KeepAlive(montCtx)
	})

	ctx.copyChecker.Check()
	runtime.KeepAlive(m)
	runtime.KeepAlive(bigNumCtx)
	return ctx, nil
}
