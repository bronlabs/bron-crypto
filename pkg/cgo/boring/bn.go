//go:build !purego && !nobignum

package boring

// #cgo CFLAGS: -I "${SRCDIR}/../../../thirdparty/boringssl/include"
// #include <openssl/bn.h>
import (
	"C"
)

import (
	"runtime"
	"unsafe"

	"github.com/copperexchange/krypton-primitives/pkg/base/utils"
)

type nativeBigNum = C.BIGNUM

type BigNum struct {
	nativeBigNum

	noCopy      noCopy
	copyChecker copyChecker
}

var (
	Zero = &BigNum{}

	oneLimbs = []C.BN_ULONG{1}
	One      = &BigNum{}
)

//nolint:gochecknoinits // allow initialization of native values
func init() {
	Zero.nativeBigNum.d = nil
	Zero.nativeBigNum.width = 0
	Zero.nativeBigNum.dmax = 0
	Zero.nativeBigNum.neg = 0
	Zero.nativeBigNum.flags = C.BN_FLG_STATIC_DATA

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

	bn.copyChecker.check()
	return bn
}

// Add sets bn = lhs + rhs, where lhs and rhs are non-negative and bn may
// be the same pointer as either lhs or rhs. It returns error on allocation failure.
func (bn *BigNum) Add(lhs, rhs *BigNum) (*BigNum, error) {
	bn.copyChecker.check()
	lhs.copyChecker.check()
	rhs.copyChecker.check()

	ret := C.BN_uadd(&bn.nativeBigNum, &lhs.nativeBigNum, &rhs.nativeBigNum)
	if ret != 1 {
		return nil, lastError()
	}

	runtime.KeepAlive(lhs)
	runtime.KeepAlive(rhs)
	return bn, nil
}

// Sub sets bn = lhs - rhs, where lhs and rhs are non-negative, lhs > rhs and bn may
// be the same pointer as either lhs or rhs. It returns error on allocation failure.
func (bn *BigNum) Sub(lhs, rhs *BigNum) (*BigNum, error) {
	bn.copyChecker.check()
	lhs.copyChecker.check()
	rhs.copyChecker.check()

	ret := C.BN_usub(&bn.nativeBigNum, &lhs.nativeBigNum, &rhs.nativeBigNum)
	if ret != 1 {
		return nil, lastError()
	}

	runtime.KeepAlive(lhs)
	runtime.KeepAlive(rhs)
	return bn, nil
}

// Mul sets bn = lhs * rhs, bn may be the same pointer as either lhs or rhs.
// It returns error on allocation failure.
func (bn *BigNum) Mul(lhs, rhs *BigNum, ctx *BigNumCtx) (*BigNum, error) {
	bn.copyChecker.check()
	lhs.copyChecker.check()
	rhs.copyChecker.check()
	ctx.copyChecker.check()

	ret := C.BN_mul(&bn.nativeBigNum, &lhs.nativeBigNum, &rhs.nativeBigNum, ctx.nativeBnCtx)
	if ret != 1 {
		return nil, lastError()
	}

	runtime.KeepAlive(lhs)
	runtime.KeepAlive(rhs)
	runtime.KeepAlive(ctx)
	return bn, nil
}

// Div divides num by div and places the result in bn and the remainder in rem.
// rem may be nil, in which case the respective value is not returned.
// It returns one on success or zero on error.
func (bn *BigNum) Div(num, div, rem *BigNum, ctx *BigNumCtx) (*BigNum, error) {
	bn.copyChecker.check()
	num.copyChecker.check()
	div.copyChecker.check()
	ctx.copyChecker.check()
	if rem != nil {
		rem.copyChecker.check()
	}

	realRem := (*nativeBigNum)(nil)
	if rem != nil {
		realRem = &rem.nativeBigNum
	}
	ret := C.BN_div(&bn.nativeBigNum, realRem, &num.nativeBigNum, &div.nativeBigNum, ctx.nativeBnCtx)
	if ret != 1 {
		return nil, lastError()
	}

	runtime.KeepAlive(num)
	runtime.KeepAlive(div)
	runtime.KeepAlive(realRem)
	runtime.KeepAlive(ctx)
	return bn, nil
}

func (bn *BigNum) LShift(a *BigNum, n int) (*BigNum, error) {
	bn.copyChecker.check()
	a.copyChecker.check()

	ret := C.BN_lshift(&bn.nativeBigNum, &a.nativeBigNum, C.int(n))
	if ret != 1 {
		return nil, lastError()
	}

	runtime.KeepAlive(a)
	return bn, nil
}

func (bn *BigNum) RShift(a *BigNum, n int) (*BigNum, error) {
	bn.copyChecker.check()
	a.copyChecker.check()

	ret := C.BN_rshift(&bn.nativeBigNum, &a.nativeBigNum, C.int(n))
	if ret != 1 {
		return nil, lastError()
	}

	runtime.KeepAlive(a)
	return bn, nil
}

func (bn *BigNum) WidthBits() uint {
	bn.copyChecker.check()

	bitLen := C.BN_BITS2 * bn.nativeBigNum.width
	return uint(bitLen)
}

func (bn *BigNum) NumBits() uint {
	bn.copyChecker.check()

	bitLen := C.BN_num_bits(&bn.nativeBigNum)

	runtime.KeepAlive(bn)
	return uint(bitLen)
}

func (bn *BigNum) Copy() (*BigNum, error) {
	newBigNum := NewBigNum()
	ret := C.BN_copy(&newBigNum.nativeBigNum, &bn.nativeBigNum)
	if ret == nil {
		return nil, lastError()
	}

	runtime.KeepAlive(bn)
	return newBigNum, nil
}

func (bn *BigNum) MaskBits(size uint) (*BigNum, error) {
	bn.copyChecker.check()

	ret := C.BN_mask_bits(&bn.nativeBigNum, C.int(size))
	if ret != 1 {
		return nil, lastError()
	}

	return bn, nil
}

// GenPrime sets bn to a prime number of bits length.
// If safe is true then the prime will be such that (bn-1)/2 is also a prime.
// (This is needed for Diffie-Hellman groups to ensure that the only subgroups are of size 2 and (p-1)/2.)
// Beware: this function is rather slow for safe primes. Use dedicated DiffieHellmanGroup.GenerateParameters instead.
func (bn *BigNum) GenPrime(bits int, safe bool) (*BigNum, error) {
	bn.copyChecker.check()

	safeInt := utils.BoolTo[C.int](safe)
	ret := C.BN_generate_prime_ex(&bn.nativeBigNum, (C.int)(bits), safeInt, nil, nil, nil)
	if ret != 1 {
		return nil, lastError()
	}

	return bn, nil
}

// Gcd sets bn = gcd(a, b).
func (bn *BigNum) Gcd(a, b *BigNum, bnCtx *BigNumCtx) (*BigNum, error) {
	bn.copyChecker.check()
	a.copyChecker.check()
	b.copyChecker.check()
	bnCtx.copyChecker.check()

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
	bn.copyChecker.check()

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
	bn.copyChecker.check()
	a.copyChecker.check()
	p.copyChecker.check()
	m.copyChecker.check()
	montCtx.copyChecker.check()
	bnCtx.copyChecker.check()

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
	bn.copyChecker.check()
	l.copyChecker.check()
	r.copyChecker.check()
	m.copyChecker.check()
	bnCtx.copyChecker.check()

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
	bn.copyChecker.check()
	l.copyChecker.check()
	r.copyChecker.check()
	m.copyChecker.check()

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
	bn.copyChecker.check()
	l.copyChecker.check()
	r.copyChecker.check()
	m.copyChecker.check()

	ret := C.BN_mod_add_quick(&bn.nativeBigNum, &l.nativeBigNum, &r.nativeBigNum, &m.nativeBigNum)
	if ret != 1 {
		return nil, lastError()
	}

	runtime.KeepAlive(l)
	runtime.KeepAlive(r)
	runtime.KeepAlive(m)
	return bn, nil
}

// ModInv sets bn equal to a^-1 mod |n|
func (bn *BigNum) ModInv(a, n *BigNum, bnCtx *BigNumCtx) (*BigNum, error) {
	bn.copyChecker.check()
	a.copyChecker.check()
	n.copyChecker.check()
	bnCtx.copyChecker.check()

	ret := C.BN_mod_inverse(&bn.nativeBigNum, &a.nativeBigNum, &n.nativeBigNum, bnCtx.nativeBnCtx)
	if ret == nil {
		return nil, lastError()
	}

	runtime.KeepAlive(a)
	runtime.KeepAlive(n)
	runtime.KeepAlive(bnCtx)
	return bn, nil
}

func (bn *BigNum) ModSqrt(a, n *BigNum, bnCtx *BigNumCtx) (*BigNum, error) {
	bn.copyChecker.check()
	a.copyChecker.check()
	n.copyChecker.check()
	bnCtx.copyChecker.check()

	ret := C.BN_mod_inverse(&bn.nativeBigNum, &a.nativeBigNum, &n.nativeBigNum, bnCtx.nativeBnCtx)
	if ret == nil {
		return nil, lastError()
	}

	runtime.KeepAlive(a)
	runtime.KeepAlive(n)
	runtime.KeepAlive(bnCtx)
	return bn, nil
}

// Mod sets bn = x mod m.
func (bn *BigNum) Mod(x, m *BigNum, bnCtx *BigNumCtx) (*BigNum, error) {
	bn.copyChecker.check()
	x.copyChecker.check()
	m.copyChecker.check()
	bnCtx.copyChecker.check()

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
	bn.copyChecker.check()

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

func (bn *BigNum) SetU64(value uint64) (*BigNum, error) {
	bn.copyChecker.check()

	ret := C.BN_set_u64(&bn.nativeBigNum, C.uint64_t(value))
	if ret != 1 {
		return nil, lastError()
	}

	return bn, nil
}

func (bn *BigNum) Cmp(rhs *BigNum) int {
	bn.copyChecker.check()
	rhs.copyChecker.check()

	ret := C.BN_ucmp(&bn.nativeBigNum, &rhs.nativeBigNum)

	runtime.KeepAlive(bn)
	runtime.KeepAlive(rhs)
	return int(ret)
}

func (bn *BigNum) Equal(rhs *BigNum) int {
	bn.copyChecker.check()
	rhs.copyChecker.check()

	ret := C.BN_equal_consttime(&bn.nativeBigNum, &rhs.nativeBigNum)

	runtime.KeepAlive(bn)
	runtime.KeepAlive(rhs)
	return int(ret)
}

func (bn *BigNum) IsZero() int {
	bn.copyChecker.check()

	ret := C.BN_is_zero(&bn.nativeBigNum)

	runtime.KeepAlive(bn)
	return int(ret)
}
