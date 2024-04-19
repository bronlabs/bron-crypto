//go:build !purego && !nobignum

package boring

// #cgo CFLAGS: -I "${SRCDIR}/../../../thirdparty/boringssl/include"
// #include <openssl/dh.h>
// #include <openssl/bn.h>
import "C"
import "runtime"

type nativeDh = *C.DH

type DiffieHellmanGroup struct {
	nativeDh

	noCopy
	copyChecker copyChecker
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

	dhGroup.copyChecker.check()
	return dhGroup
}

func (dh *DiffieHellmanGroup) GenerateParameters(primeBits int) *DiffieHellmanGroup {
	dh.copyChecker.check()

	ret := C.DH_generate_parameters_ex(dh.nativeDh, C.int(primeBits), C.DH_GENERATOR_2, nil)
	if ret != 1 {
		panic("DH_generate_parameters_ex")
	}

	return dh
}

func (dh *DiffieHellmanGroup) GetP() *BigNum {
	dh.copyChecker.check()

	nativeP := C.DH_get0_p(dh.nativeDh)
	if nativeP == nil {
		panic("DH_get0_p")
	}
	p := NewBigNum()
	ret := C.BN_copy(&p.nativeBigNum, nativeP)
	if ret == nil {
		panic("DH_get0_p")
	}

	runtime.KeepAlive(dh)
	return p
}
