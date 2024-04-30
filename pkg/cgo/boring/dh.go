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

func NewDiffieHellmanGroup() (*DiffieHellmanGroup, error) {
	dh := C.DH_new()
	if dh == nil {
		return nil, lastError()
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
	return dhGroup, nil
}

func (dh *DiffieHellmanGroup) GenerateParameters(primeBits int) (*DiffieHellmanGroup, error) {
	dh.copyChecker.check()

	ret := C.DH_generate_parameters_ex(dh.nativeDh, C.int(primeBits), C.DH_GENERATOR_2, nil)
	if ret != 1 {
		return nil, lastError()
	}

	return dh, nil
}

func (dh *DiffieHellmanGroup) GetP() (*BigNum, error) {
	dh.copyChecker.check()

	nativeP := C.DH_get0_p(dh.nativeDh)
	if nativeP == nil {
		return nil, lastError()
	}
	p := NewBigNum()
	ret := C.BN_copy(&p.nativeBigNum, nativeP)
	if ret == nil {
		return nil, lastError()
	}

	runtime.KeepAlive(dh)
	return p, nil
}
