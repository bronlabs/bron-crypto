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

	"github.com/copperexchange/krypton-primitives/pkg/base/utils"
)

type nativeBigNum = C.BIGNUM

type BigNum struct {
	nativeBigNum

	noCopy      noCopy
	copyChecker copyChecker
}

var (
	oneBytes = []C.BN_ULONG{1}
	One      = &BigNum{}
)

//nolint:gochecknoinits // allow initialization of native values
func init() {
	One.nativeBigNum.d = &oneBytes[0]
	One.nativeBigNum.width = 1
	One.nativeBigNum.dmax = 1
	One.nativeBigNum.neg = 0
	One.nativeBigNum.flags = C.BN_FLG_STATIC_DATA
}

// NewBigNum creates a new BigNum and initialises it.
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

// GenPrime sets bn to a prime number of bits length.
// If safe is true then the prime will be such that (bn-1)/2 is also a prime.
// (This is needed for Diffie-Hellman groups to ensure that the only subgroups are of size 2 and (p-1)/2.)
func (bn *BigNum) GenPrime(bits int, safe bool) *BigNum {
	bn.copyChecker.check()

	safeInt := utils.BoolTo[C.int](safe)
	ret := C.BN_generate_prime_ex(&bn.nativeBigNum, (C.int)(bits), safeInt, nil, nil, nil) //nolint:gocritic // false positive
	if ret != 1 {
		panic("BN_generate_prime_ex")
	}

	return bn
}

// Gcd sets bn = gcd(a, b).
func (bn *BigNum) Gcd(a, b *BigNum, bnCtx *BigNumCtx) *BigNum {
	bn.copyChecker.check()
	a.copyChecker.check()
	b.copyChecker.check()
	bnCtx.copyChecker.check()

	ret := C.BN_gcd(&bn.nativeBigNum, &a.nativeBigNum, &b.nativeBigNum, bnCtx.nativeBnCtx) //nolint:gocritic // false positive
	if ret != 1 {
		panic("BN_gcd")
	}

	runtime.KeepAlive(a)
	runtime.KeepAlive(b)
	runtime.KeepAlive(bnCtx)
	return bn
}

// Bytes serialises the value of bn as a big-endian integer.
func (bn *BigNum) Bytes() []byte {
	bn.copyChecker.check()

	announcedLen := ((C.BN_BITS2 * bn.nativeBigNum.width) + 7) / 8
	buffer := make([]byte, announcedLen)
	if announcedLen > 0 {
		ret := C.BN_bn2bin_padded((*C.uint8_t)(&buffer[0]), (C.size_t)(announcedLen), &bn.nativeBigNum) //nolint:gocritic // false positive
		if ret != 1 {
			panic("BN_bn2bin_padded")
		}
	}

	runtime.KeepAlive(bn)
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

	runtime.KeepAlive(a)
	runtime.KeepAlive(p)
	runtime.KeepAlive(m)
	runtime.KeepAlive(montCtx)
	runtime.KeepAlive(bnCtx)
	return bn
}

// ModMul sets bn = a*b mod m.
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

	runtime.KeepAlive(l)
	runtime.KeepAlive(r)
	runtime.KeepAlive(m)
	runtime.KeepAlive(bnCtx)
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

	runtime.KeepAlive(l)
	runtime.KeepAlive(r)
	runtime.KeepAlive(m)
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

	runtime.KeepAlive(l)
	runtime.KeepAlive(r)
	runtime.KeepAlive(m)
	return bn
}

// Mod sets bn = x mod m.
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

	runtime.KeepAlive(x)
	runtime.KeepAlive(m)
	runtime.KeepAlive(bnCtx)
	return bn
}

// SetBytes sets bn to the value of bytes from data, interpreted as a big-endian number.
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
