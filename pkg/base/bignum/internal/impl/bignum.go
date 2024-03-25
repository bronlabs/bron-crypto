package impl

// #cgo CFLAGS: -I "${SRCDIR}/../../../../../boringssl/include"
// #cgo LDFLAGS: -L"${SRCDIR}/../../../../../boringssl/build/crypto" -lcrypto
// #include <openssl/bn.h>
// #include <openssl/mem.h>
import "C"
import "unsafe"

type nativeBnCtx = *C.BN_CTX

type BoringBigNumCtx struct {
	nativeBnCtx
}

func NewBigNumCtx() BoringBigNumCtx {
	bnCtx := C.BN_CTX_new()
	if bnCtx == nil {
		panic("new")
	}
	return BoringBigNumCtx{bnCtx}
}

func FreeBigNumCtx(ctx BoringBigNumCtx) {
	C.BN_CTX_free(ctx.nativeBnCtx)
}

type nativeMontCtx = *C.BN_MONT_CTX

type BoringMontCtx struct {
	nativeMontCtx
}

func NewMontCtx(m *BoringBigNum, ctx BoringBigNumCtx) BoringMontCtx {
	montyCtx := C.BN_MONT_CTX_new_consttime(&m.nativeBigNum, ctx.nativeBnCtx)
	if montyCtx == nil {
		panic("new_consttime")
	}
	return BoringMontCtx{montyCtx}
}

func FreeMontCtx(ctx BoringMontCtx) {
	C.BN_MONT_CTX_free(ctx.nativeMontCtx)
}

type nativeBigNum = C.BIGNUM

type BoringBigNum struct {
	nativeBigNum
}

func InitBigNum(bn *BoringBigNum) *BoringBigNum {
	C.BN_init(&bn.nativeBigNum)
	return bn
}

func FreeBigNum(n *BoringBigNum) {
	C.BN_clear_free(&n.nativeBigNum)
}

func (bn *BoringBigNum) Bytes() []byte {
	announcedLen := (C.BN_BITS2*bn.nativeBigNum.width + 7) / 8
	realLen := C.int(C.BN_num_bytes(&bn.nativeBigNum))
	buffer := make([]byte, announcedLen)

	if realLen != 0 {
		C.BN_bn2bin(&bn.nativeBigNum, (*C.uint8_t)(&buffer[announcedLen-realLen]))
	}
	return buffer
}

func (bn *BoringBigNum) GenPrime(bits int, safe int) *BoringBigNum {
	r := C.BN_generate_prime_ex(&bn.nativeBigNum, C.int(bits), C.int(safe), nil, nil, nil)
	if r != 1 {
		panic("generate_prime_ex")
	}

	return bn
}

func (bn *BoringBigNum) Exp(a, p, m *BoringBigNum, montCtx BoringMontCtx, bnCtx BoringBigNumCtx) *BoringBigNum {
	ret := C.BN_mod_exp_mont_consttime(&bn.nativeBigNum, &a.nativeBigNum, &p.nativeBigNum, &m.nativeBigNum, bnCtx.nativeBnCtx, montCtx.nativeMontCtx)
	if ret != 1 {
		panic("mod_exp_mont_consttime")
	}

	return bn
}

func (bn *BoringBigNum) Mod(x, m *BoringBigNum, bnCtx BoringBigNumCtx) *BoringBigNum {
	r := C.BN_nnmod(&bn.nativeBigNum, &x.nativeBigNum, &m.nativeBigNum, bnCtx.nativeBnCtx)
	if r != 1 {
		panic("nnmod")
	}

	return bn
}

func (bn *BoringBigNum) SetBytes(data []byte) *BoringBigNum {
	if len(data) == 0 {
		FreeBigNum(bn)
		InitBigNum(bn)
		return bn
	}

	rawData := (*C.uint8_t)(unsafe.Pointer(&data[0]))
	r := C.BN_bin2bn(rawData, C.size_t(len(data)), &bn.nativeBigNum)
	if r == nil {
		panic("bin2bn")
	}

	return bn
}
