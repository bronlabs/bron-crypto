//go:build !purego && !nobignum

package boring

// #include "openssl/dh.h"
// #include "openssl/bn.h"
import "C"
import (
	"runtime"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/utils/nocopy"
)

var ErrNoPrime = errs.New("DH group has no prime set")

type nativeDh = *C.DH

type DiffieHellmanGroup struct {
	nativeDh

	nocopy.NoCopy
	copyChecker nocopy.CopyChecker
}

func NewDiffieHellmanGroup() *DiffieHellmanGroup {
	dh := C.DH_new()
	if dh == nil {
		panic("DH_new")
	}
	dhGroup := &DiffieHellmanGroup{
		nativeDh: dh,
	}
	runtime.SetFinalizer(dhGroup, func(dhGroup *DiffieHellmanGroup) {
		C.DH_free(dhGroup.nativeDh)
		dhGroup.nativeDh = nil
		runtime.KeepAlive(dhGroup)
	})

	dhGroup.copyChecker.Check()
	return dhGroup
}

func (dh *DiffieHellmanGroup) GenerateParameters(primeBits int) (*DiffieHellmanGroup, error) {
	dh.copyChecker.Check()

	lockOSThread()
	ret := C.DH_generate_parameters_ex(dh.nativeDh, C.int(primeBits), C.DH_GENERATOR_2, nil)
	if ret != 1 {
		err := lastError()
		unlockOSThread()
		return nil, err
	}
	unlockOSThread()

	return dh, nil
}

func (dh *DiffieHellmanGroup) GetP() (*BigNum, error) {
	dh.copyChecker.Check()

	nativeP := C.DH_get0_p(dh.nativeDh)
	if nativeP == nil {
		return nil, ErrNoPrime
	}

	p := NewBigNum()
	lockOSThread()
	ret := C.BN_copy(&p.nativeBigNum, nativeP)
	if ret == nil {
		err := lastError()
		unlockOSThread()
		return nil, err
	}
	unlockOSThread()

	runtime.KeepAlive(dh)
	return p, nil
}
