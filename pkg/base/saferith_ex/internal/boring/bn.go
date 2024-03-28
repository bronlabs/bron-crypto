package boring

// #cgo CFLAGS: -I "${SRCDIR}/../../../../../boringssl/include"
// #cgo LDFLAGS: -L"${SRCDIR}/../../../../../boringssl/build/crypto" -lcrypto
// #include <openssl/bn.h>
import (
	"C" //nolint:gocritic // false positive
)

import (
	"runtime"
	"unsafe" //nolint:gocritic // false positive
)

var (
	oneBytes = []C.BN_ULONG{1}
	One      = &BigNum{}
)

type nativeBigNum = C.BIGNUM

type BigNum struct {
	nativeBigNum

	noCopy      noCopy
	copyChecker copyChecker
}

func NewBigNum() *BigNum {
	bn := &BigNum{}
	C.BN_init(&bn.nativeBigNum) //nolint:gocritic // false positive

	runtime.SetFinalizer(bn, func(bn *BigNum) {
		C.BN_clear_free(&bn.nativeBigNum) //nolint:gocritic // false positive
		runtime.KeepAlive(bn)
	})

	bn.copyChecker.check()
	return bn
}

//nolint:gochecknoinits // allow initialization of native values
func init() {
	One.nativeBigNum.d = &oneBytes[0]
	One.nativeBigNum.width = 1
	One.nativeBigNum.dmax = 1
	One.nativeBigNum.neg = 0
	One.nativeBigNum.flags = C.BN_FLG_STATIC_DATA
}

func (bn *BigNum) Bytes() []byte {
	bn.copyChecker.check()

	announcedLen := ((C.BN_BITS2 * bn.nativeBigNum.width) + 7) / 8
	realLen := C.int(C.BN_num_bytes(&bn.nativeBigNum)) //nolint:gocritic // false positive
	buffer := make([]byte, announcedLen)

	if realLen != 0 {
		C.BN_bn2bin(&bn.nativeBigNum, (*C.uint8_t)(&buffer[announcedLen-realLen])) //nolint:gocritic // false positive
	}
	return buffer
}

// Exp sets bn equal to a^p mod m.
// It treats a, p, and m as secrets and requires 0 <= a < m.
func (bn *BigNum) Exp(a, p, m *BigNum, montCtx *BigNumMontCtx, bnCtx *BigNumCtx) *BigNum {
	bn.copyChecker.check()
	a.copyChecker.check()
	p.copyChecker.check()
	m.copyChecker.check()
	montCtx.copyChecker.check()
	bnCtx.copyChecker.check()

	//nolint:gocritic // false positive
	ret := C.BN_mod_exp_mont_consttime(&bn.nativeBigNum, &a.nativeBigNum, &p.nativeBigNum, &m.nativeBigNum, bnCtx.nativeBnCtx, montCtx.nativeBnMontCtx)
	if ret != 1 {
		panic("BN_mod_exp_mont_consttime")
	}

	return bn
}

func (bn *BigNum) ModMul(l, r, m *BigNum, bnCtx *BigNumCtx) *BigNum {
	bn.copyChecker.check()
	l.copyChecker.check()
	r.copyChecker.check()
	m.copyChecker.check()
	bnCtx.copyChecker.check()

	//nolint:gocritic // false positive
	ret := C.BN_mod_mul(&bn.nativeBigNum, &l.nativeBigNum, &r.nativeBigNum, &m.nativeBigNum, bnCtx.nativeBnCtx)
	if ret != 1 {
		panic("BN_mod_mul")
	}
	return bn
}

// ModSub sets bn = l - r mod m
// It requires that l and r be less than m.
func (bn *BigNum) ModSub(l, r, m *BigNum) *BigNum {
	bn.copyChecker.check()
	l.copyChecker.check()
	r.copyChecker.check()
	m.copyChecker.check()

	//nolint:gocritic // false positive
	ret := C.BN_mod_sub_quick(&bn.nativeBigNum, &l.nativeBigNum, &r.nativeBigNum, &m.nativeBigNum)
	if ret != 1 {
		panic("BN_mod_sub_quick")
	}
	return bn
}

// ModAdd sets bn = l + r mod m.
// It requires that l and r be less than m.
func (bn *BigNum) ModAdd(l, r, m *BigNum) *BigNum {
	bn.copyChecker.check()
	l.copyChecker.check()
	r.copyChecker.check()
	m.copyChecker.check()

	//nolint:gocritic // false positive
	ret := C.BN_mod_add_quick(&bn.nativeBigNum, &l.nativeBigNum, &r.nativeBigNum, &m.nativeBigNum)
	if ret != 1 {
		panic("BN_mod_add_quick")
	}
	return bn
}

func (bn *BigNum) Mod(x, m *BigNum, bnCtx *BigNumCtx) *BigNum {
	bn.copyChecker.check()
	x.copyChecker.check()
	m.copyChecker.check()
	bnCtx.copyChecker.check()

	//nolint:gocritic // false positive
	r := C.BN_nnmod(&bn.nativeBigNum, &x.nativeBigNum, &m.nativeBigNum, bnCtx.nativeBnCtx)
	if r != 1 {
		panic("BN_nnmod")
	}

	return bn
}

func (bn *BigNum) SetBytes(data []byte) *BigNum {
	bn.copyChecker.check()

	if len(data) == 0 {
		C.BN_clear_free(&bn.nativeBigNum) //nolint:gocritic // false positive
		C.BN_init(&bn.nativeBigNum)       //nolint:gocritic // false positive
		return bn
	}

	rawData := (*C.uint8_t)(unsafe.Pointer(&data[0]))
	r := C.BN_bin2bn(rawData, C.size_t(len(data)), &bn.nativeBigNum) //nolint:gocritic // false positive
	if r == nil {
		panic("BN_bin2bn")
	}

	runtime.KeepAlive(data)
	return bn
}
