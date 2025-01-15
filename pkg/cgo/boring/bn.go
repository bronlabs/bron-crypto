//go:build !purego && !nobignum

package boring

// #include <openssl/bn.h>
import (
	"C"
)

import (
	"github.com/bronlabs/krypton-primitives/pkg/base/utils/nocopy"
	"runtime"
	"unsafe"

	"github.com/bronlabs/krypton-primitives/pkg/base/utils"
)

type nativeBigNum = C.BIGNUM

type BigNum struct {
	nativeBigNum

	noCopy      nocopy.NoCopy
	copyChecker nocopy.CopyChecker
}

var (
	oneLimbs = []C.BN_ULONG{1}
	One      = &BigNum{}
)

//nolint:gochecknoinits // allow initialization of native values
func init() {
	One.nativeBigNum.d = &oneLimbs[0]
	One.nativeBigNum.width = 1
	One.nativeBigNum.dmax = 1
	One.nativeBigNum.neg = 0
	One.nativeBigNum.flags = C.BN_FLG_STATIC_DATA
}

// NewBigNum creates a new BigNum and initialises it.
func NewBigNum() *BigNum {
	bn := &BigNum{}
	C.BN_init(&bn.nativeBigNum)

	runtime.SetFinalizer(bn, func(bn *BigNum) {
		C.BN_clear_free(&bn.nativeBigNum)
		runtime.KeepAlive(bn)
	})

	bn.copyChecker.Check()
	return bn
}

// GenPrime sets bn to a prime number of bits length.
// If safe is true then the prime will be such that (bn-1)/2 is also a prime.
// (This is needed for Diffie-Hellman groups to ensure that the only subgroups are of size 2 and (p-1)/2.)
// Beware: this function is rather slow for safe primes. Use dedicated DiffieHellmanGroup.GenerateParameters instead.
func (bn *BigNum) GenPrime(bits int, safe bool) (*BigNum, error) {
	bn.copyChecker.Check()

	safeInt := utils.BoolTo[C.int](safe)
	ret := C.BN_generate_prime_ex(&bn.nativeBigNum, (C.int)(bits), safeInt, nil, nil, nil)
	if ret != 1 {
		return nil, lastError()
	}

	return bn, nil
}

// Gcd sets bn = gcd(a, b).
func (bn *BigNum) Gcd(a, b *BigNum, bnCtx *BigNumCtx) (*BigNum, error) {
	bn.copyChecker.Check()
	a.copyChecker.Check()
	b.copyChecker.Check()
	bnCtx.copyChecker.Check()

	ret := C.BN_gcd(&bn.nativeBigNum, &a.nativeBigNum, &b.nativeBigNum, bnCtx.nativeBnCtx)
	if ret != 1 {
		return nil, lastError()
	}

	runtime.KeepAlive(a)
	runtime.KeepAlive(b)
	runtime.KeepAlive(bnCtx)
	return bn, nil
}

// Bytes serialises the value of bn as a big-endian integer.
func (bn *BigNum) Bytes() ([]byte, error) {
	bn.copyChecker.Check()

	announcedLen := ((C.BN_BITS2 * bn.nativeBigNum.width) + 7) / 8
	buffer := make([]byte, announcedLen)
	if announcedLen > 0 {
		ret := C.BN_bn2bin_padded((*C.uint8_t)(&buffer[0]), (C.size_t)(announcedLen), &bn.nativeBigNum)
		if ret != 1 {
			return nil, lastError()
		}
	}

	runtime.KeepAlive(bn)
	return buffer, nil
}

// Exp sets bn equal to a^p mod m.
// It treats a, p, and m as secrets and requires 0 <= a < m.
func (bn *BigNum) Exp(a, p, m *BigNum, montCtx *BigNumMontCtx, bnCtx *BigNumCtx) (*BigNum, error) {
	bn.copyChecker.Check()
	a.copyChecker.Check()
	p.copyChecker.Check()
	m.copyChecker.Check()
	montCtx.copyChecker.Check()
	bnCtx.copyChecker.Check()

	ret := C.BN_mod_exp_mont_consttime(&bn.nativeBigNum, &a.nativeBigNum, &p.nativeBigNum, &m.nativeBigNum, bnCtx.nativeBnCtx, montCtx.nativeBnMontCtx)
	if ret != 1 {
		return nil, lastError()
	}

	runtime.KeepAlive(a)
	runtime.KeepAlive(p)
	runtime.KeepAlive(m)
	runtime.KeepAlive(montCtx)
	runtime.KeepAlive(bnCtx)
	return bn, nil
}

// ModMul sets bn = a*b mod m.
func (bn *BigNum) ModMul(l, r, m *BigNum, bnCtx *BigNumCtx) (*BigNum, error) {
	bn.copyChecker.Check()
	l.copyChecker.Check()
	r.copyChecker.Check()
	m.copyChecker.Check()
	bnCtx.copyChecker.Check()

	ret := C.BN_mod_mul(&bn.nativeBigNum, &l.nativeBigNum, &r.nativeBigNum, &m.nativeBigNum, bnCtx.nativeBnCtx)
	if ret != 1 {
		return nil, lastError()
	}

	runtime.KeepAlive(l)
	runtime.KeepAlive(r)
	runtime.KeepAlive(m)
	runtime.KeepAlive(bnCtx)
	return bn, nil
}

// ModSub sets bn = l - r mod m
// It requires that l and r be less than m.
func (bn *BigNum) ModSub(l, r, m *BigNum) (*BigNum, error) {
	bn.copyChecker.Check()
	l.copyChecker.Check()
	r.copyChecker.Check()
	m.copyChecker.Check()

	ret := C.BN_mod_sub_quick(&bn.nativeBigNum, &l.nativeBigNum, &r.nativeBigNum, &m.nativeBigNum)
	if ret != 1 {
		return nil, lastError()
	}

	runtime.KeepAlive(l)
	runtime.KeepAlive(r)
	runtime.KeepAlive(m)
	return bn, nil
}

// ModAdd sets bn = l + r mod m.
// It requires that l and r be less than m.
func (bn *BigNum) ModAdd(l, r, m *BigNum) (*BigNum, error) {
	bn.copyChecker.Check()
	l.copyChecker.Check()
	r.copyChecker.Check()
	m.copyChecker.Check()

	ret := C.BN_mod_add_quick(&bn.nativeBigNum, &l.nativeBigNum, &r.nativeBigNum, &m.nativeBigNum)
	if ret != 1 {
		return nil, lastError()
	}

	runtime.KeepAlive(l)
	runtime.KeepAlive(r)
	runtime.KeepAlive(m)
	return bn, nil
}

// Mod sets bn = x mod m.
func (bn *BigNum) Mod(x, m *BigNum, bnCtx *BigNumCtx) (*BigNum, error) {
	bn.copyChecker.Check()
	x.copyChecker.Check()
	m.copyChecker.Check()
	bnCtx.copyChecker.Check()

	r := C.BN_nnmod(&bn.nativeBigNum, &x.nativeBigNum, &m.nativeBigNum, bnCtx.nativeBnCtx)
	if r != 1 {
		return nil, lastError()
	}

	runtime.KeepAlive(x)
	runtime.KeepAlive(m)
	runtime.KeepAlive(bnCtx)

	return bn, nil
}

// SetBytes sets bn to the value of bytes from data, interpreted as a big-endian number.
func (bn *BigNum) SetBytes(data []byte) (*BigNum, error) {
	bn.copyChecker.Check()

	if len(data) == 0 {
		C.BN_clear_free(&bn.nativeBigNum)
		C.BN_init(&bn.nativeBigNum)
		return bn, nil
	}

	rawData := (*C.uint8_t)(unsafe.Pointer(&data[0]))
	r := C.BN_bin2bn(rawData, C.size_t(len(data)), &bn.nativeBigNum)
	if r == nil {
		return nil, lastError()
	}

	runtime.KeepAlive(data)
	return bn, nil
}
