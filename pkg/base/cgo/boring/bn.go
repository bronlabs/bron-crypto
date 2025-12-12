//go:build !purego && !nobignum

package boring

// TODO: do below in glue.go

// #include "openssl/bn.h"
// // Forward-declare BoringSSL’s exported symbol (not in public headers).
// int bn_lcm_consttime(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
import (
	"C"
)

import (
	"runtime"
	"unsafe"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/nocopy"
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
func (bn *BigNum) GenPrime(bits int, safe ct.Bool) (*BigNum, error) {
	bn.copyChecker.Check()

	lockOSThread()
	ret := C.BN_generate_prime_ex(&bn.nativeBigNum, (C.int)(bits), (C.int)(safe), nil, nil, nil)
	if ret != 1 {
		err := lastError()
		unlockOSThread()
		return nil, err
	}
	unlockOSThread()

	return bn, nil
}

// Gcd sets bn = gcd(a, b). Internally, BoringSSL's GCD's output is an odd number plus a leftShift
// to make it even (corresponding to `bn_rshift_secret_shift`), if needed. Therefore:
// - Algorithm is constant time ONLY IF at least one argument is odd.
func (bn *BigNum) Gcd(a, b *BigNum, bnCtx *BigNumCtx) (*BigNum, error) {
	bn.copyChecker.Check()
	a.copyChecker.Check()
	b.copyChecker.Check()
	bnCtx.copyChecker.Check()

	lockOSThread()
	ret := C.BN_gcd(&bn.nativeBigNum, &a.nativeBigNum, &b.nativeBigNum, bnCtx.nativeBnCtx)
	if ret != 1 {
		err := lastError()
		unlockOSThread()
		return nil, err
	}
	unlockOSThread()

	runtime.KeepAlive(a)
	runtime.KeepAlive(b)
	runtime.KeepAlive(bnCtx)
	return bn, nil
}

func (bn *BigNum) Lcm(a, b *BigNum, bnCtx *BigNumCtx) (*BigNum, error) {
	bn.copyChecker.Check()
	a.copyChecker.Check()
	b.copyChecker.Check()
	bnCtx.copyChecker.Check()

	lockOSThread()
	ret := C.bn_lcm_consttime(&bn.nativeBigNum, &a.nativeBigNum, &b.nativeBigNum, bnCtx.nativeBnCtx)
	if ret != 1 {
		err := lastError()
		unlockOSThread()
		return nil, err
	}
	unlockOSThread()

	runtime.KeepAlive(a)
	runtime.KeepAlive(b)
	runtime.KeepAlive(bnCtx)
	return bn, nil
}

// Inv sets bn = a^{-1} mod n using BoringSSL's constant-time, blinded
// modular inverse. The modulus n is taken from the provided Montgomery context
// (montCtx). It returns the receiver (bn), a boolean noInverse which is true
// iff a has no inverse modulo n, and an error for other failures.
//
// Requirements:
//   - 0 <= a < n (callers should reduce a beforehand).
//   - n > 1. The function is intended for moduli with few noninvertible
//     residues (e.g., RSA moduli). See bn.h for details.
//   - montCtx must be initialised for n. If n is secret, use a const‑time
//     Montgomery context.
func (bn *BigNum) Inv(a *BigNum, montCtx *BigNumMontCtx, bnCtx *BigNumCtx) (*BigNum, int32, error) {
	bn.copyChecker.Check()
	a.copyChecker.Check()
	montCtx.copyChecker.Check()
	bnCtx.copyChecker.Check()

	// Lock OS thread to ensure error queue is on the same thread as the CGO call
	lockOSThread()
	var noInv C.int
	ret := C.BN_mod_inverse_blinded(&bn.nativeBigNum, &noInv, &a.nativeBigNum, montCtx.nativeBnMontCtx, bnCtx.nativeBnCtx)
	if ret != 1 {
		err := lastError()
		unlockOSThread()
		return nil, int32(noInv), err
	}
	unlockOSThread()

	runtime.KeepAlive(a)
	runtime.KeepAlive(montCtx)
	runtime.KeepAlive(bnCtx)
	return bn, int32(noInv), nil
}

// Bytes serialises the value of bn as a big-endian integer.
func (bn *BigNum) Bytes() ([]byte, error) {
	bn.copyChecker.Check()

	announcedLen := ((C.BN_BITS2 * bn.nativeBigNum.width) + 7) / 8
	buffer := make([]byte, announcedLen)
	if announcedLen > 0 {
		lockOSThread()
		ret := C.BN_bn2bin_padded((*C.uint8_t)(&buffer[0]), (C.size_t)(announcedLen), &bn.nativeBigNum)
		if ret != 1 {
			err := lastError()
			unlockOSThread()
			return nil, err
		}
		unlockOSThread()
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

	lockOSThread()
	ret := C.BN_mod_exp_mont_consttime(&bn.nativeBigNum, &a.nativeBigNum, &p.nativeBigNum, &m.nativeBigNum, bnCtx.nativeBnCtx, montCtx.nativeBnMontCtx)
	if ret != 1 {
		err := lastError()
		unlockOSThread()
		return nil, err
	}
	unlockOSThread()

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

	lockOSThread()
	ret := C.BN_mod_mul(&bn.nativeBigNum, &l.nativeBigNum, &r.nativeBigNum, &m.nativeBigNum, bnCtx.nativeBnCtx)
	if ret != 1 {
		err := lastError()
		unlockOSThread()
		return nil, err
	}
	unlockOSThread()

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

	lockOSThread()
	ret := C.BN_mod_sub_quick(&bn.nativeBigNum, &l.nativeBigNum, &r.nativeBigNum, &m.nativeBigNum)
	if ret != 1 {
		err := lastError()
		unlockOSThread()
		return nil, err
	}
	unlockOSThread()

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

	lockOSThread()
	ret := C.BN_mod_add_quick(&bn.nativeBigNum, &l.nativeBigNum, &r.nativeBigNum, &m.nativeBigNum)
	if ret != 1 {
		err := lastError()
		unlockOSThread()
		return nil, err
	}
	unlockOSThread()

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

	lockOSThread()
	r := C.BN_nnmod(&bn.nativeBigNum, &x.nativeBigNum, &m.nativeBigNum, bnCtx.nativeBnCtx)
	if r != 1 {
		err := lastError()
		unlockOSThread()
		return nil, err
	}
	unlockOSThread()

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

	lockOSThread()
	rawData := (*C.uint8_t)(unsafe.Pointer(&data[0]))
	r := C.BN_bin2bn(rawData, C.size_t(len(data)), &bn.nativeBigNum)
	if r == nil {
		err := lastError()
		unlockOSThread()
		return nil, err
	}
	unlockOSThread()

	runtime.KeepAlive(data)
	return bn, nil
}
