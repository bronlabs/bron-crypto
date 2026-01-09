package impl

import (
	"encoding/binary"
	"encoding/hex"
	"io"
	"math/big"
	"slices"

	fieldsImpl "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
)

const (
	// FpE is the exponent parameter for square roots.
	FpE = 2
	// FpBits is the field modulus bit length.
	FpBits = 255
	// FpBytes is the size of an Fp element in bytes.
	FpBytes = 32
	// FpWideBytes is the size of a wide Fp element in bytes.
	FpWideBytes = 64
)

var (
	// FpModulus is the field modulus in little-endian bytes.
	FpModulus     = [...]uint8{0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}
	FpRootOfUnity Fp
	// FpProgenitorExp is the exponent for the progenitor element.
	FpProgenitorExp = [...]uint8{0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0f}
)

//nolint:gochecknoinits // parameters initialization
func init() {
	FpRootOfUnity.MustSetHex("2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0")
}

var _ fieldsImpl.PrimeFieldElement[*Fp] = (*Fp)(nil)

// Fp represents a prime field element.
type Fp struct {
	v fiatFpTightFieldElement
}

// Set sets the receiver to v.
func (f *Fp) Set(v *Fp) {
	f.v = v.v
}

// SetZero sets the receiver to zero.
func (f *Fp) SetZero() {
	f.v = fiatFpTightFieldElement{}
}

// SetOne sets the receiver to one.
func (f *Fp) SetOne() {
	f.v = fiatFpTightFieldElement{1}
}

// SetUint64 sets the receiver from v.
func (f *Fp) SetUint64(u uint64) {
	f.v = fiatFpTightFieldElement{u & ((1 << 51) - 1), u >> 51}
}

// Select conditionally assigns z or nz into the receiver.
func (f *Fp) Select(choice ct.Choice, z, nz *Fp) {
	fiatFpSelectznz((*[5]uint64)(&f.v), fiatFpUint1(choice), (*[5]uint64)(&z.v), (*[5]uint64)(&nz.v))
}

// Add sets the receiver to lhs + rhs.
func (f *Fp) Add(lhs, rhs *Fp) {
	fiatFpCarryAdd(&f.v, &lhs.v, &rhs.v)
}

// Double sets the receiver to 2*x.
func (f *Fp) Double(x *Fp) {
	fiatFpCarryAdd(&f.v, &x.v, &x.v)
}

// Sub sets the receiver to lhs - rhs.
func (f *Fp) Sub(lhs, rhs *Fp) {
	fiatFpCarrySub(&f.v, &lhs.v, &rhs.v)
}

// Neg sets the receiver to -v.
func (f *Fp) Neg(v *Fp) {
	fiatFpCarryOpp(&f.v, &v.v)
}

// Mul sets the receiver to lhs * rhs.
func (f *Fp) Mul(lhs, rhs *Fp) {
	fiatFpCarryMul(&f.v, (*fiatFpLooseFieldElement)(&lhs.v), (*fiatFpLooseFieldElement)(&rhs.v))
}

// Square sets the receiver to v^2.
func (f *Fp) Square(v *Fp) {
	fiatFpCarrySquare(&f.v, (*fiatFpLooseFieldElement)(&v.v))
}

// Inv sets the receiver to the inverse of a, if it exists.
func (f *Fp) Inv(a *Fp) (ok ct.Bool) {
	var _10, _11, _1100, _1111, _11110000, _11111111, x10, x20, x30, x60, x120, x240, x250, out Fp

	// _10       = 2*1
	_10.Square(a)
	// _11       = 1 + _10
	_11.Mul(a, &_10)
	// _1100     = _11 << 2
	_1100.Square(&_11)
	_1100.Square(&_1100)
	// _1111     = _11 + _1100
	_1111.Mul(&_11, &_1100)
	// _11110000 = _1111 << 4
	_11110000.Square(&_1111)
	_11110000.Square(&_11110000)
	_11110000.Square(&_11110000)
	_11110000.Square(&_11110000)
	// _11111111 = _1111 + _11110000
	_11111111.Mul(&_1111, &_11110000)
	// x10       = _11111111 << 2 + _11
	x10.Square(&_11111111)
	x10.Square(&x10)
	x10.Mul(&x10, &_11)
	// x20       = x10 << 10 + x10
	x20.Set(&x10)
	for range 10 {
		x20.Square(&x20)
	}
	x20.Mul(&x20, &x10)
	// x30       = x20 << 10 + x10
	x30.Set(&x20)
	for range 10 {
		x30.Square(&x30)
	}
	x30.Mul(&x30, &x10)
	// x60       = x30 << 30 + x30
	x60.Set(&x30)
	for range 30 {
		x60.Square(&x60)
	}
	x60.Mul(&x60, &x30)
	// x120      = x60 << 60 + x60
	x120.Set(&x60)
	for range 60 {
		x120.Square(&x120)
	}
	x120.Mul(&x120, &x60)
	// x240      = x120 << 120 + x120
	x240.Set(&x120)
	for range 120 {
		x240.Square(&x240)
	}
	x240.Mul(&x240, &x120)
	// x250      = x240 << 10 + x10
	x250.Set(&x240)
	for range 10 {
		x250.Square(&x250)
	}
	x250.Mul(&x250, &x10)
	// return      (x250 << 2 + 1) << 3 + _11
	out.Square(&x250)
	out.Square(&out)
	out.Mul(&out, a)
	out.Square(&out)
	out.Square(&out)
	out.Square(&out)
	out.Mul(&out, &_11)

	ok = a.IsNonZero()
	f.Select(ok, f, &out)
	return ok
}

// Div sets the receiver to lhs / rhs, if rhs is nonzero.
func (f *Fp) Div(lhs, rhs *Fp) (ok ct.Bool) {
	var rhsInv Fp
	ok = rhsInv.Inv(rhs)
	var out Fp
	out.Mul(lhs, &rhsInv)

	f.Select(ok, f, &out)
	return ok
}

// Sqrt sets the receiver to sqrt(x) if it exists.
func (f *Fp) Sqrt(v *Fp) (ok ct.Bool) {
	return fieldsImpl.TonelliShanks(f, v, &FpRootOfUnity, FpE, FpProgenitorExp[:])
}

// Equal reports whether the receiver equals v.
func (f *Fp) Equal(rhs *Fp) ct.Bool {
	var diff Fp
	diff.Sub(f, rhs)
	return diff.IsZero()
}

// IsNonZero reports whether the receiver is nonzero.
func (f *Fp) IsNonZero() ct.Bool {
	var data [FpBytes]byte
	fiatFpToBytes(&data, &f.v)
	return anyNonZero(&data)
}

// IsZero reports whether the receiver is zero.
func (f *Fp) IsZero() ct.Bool {
	return f.IsNonZero() ^ 1
}

// IsOne reports whether the receiver is one.
func (f *Fp) IsOne() ct.Bool {
	var one Fp
	one.SetOne()
	return f.Equal(&one)
}

// SetUniformBytes sets the receiver from uniform bytes.
func (f *Fp) SetUniformBytes(componentsData ...[]byte) (ok ct.Bool) {
	if len(componentsData) != 1 {
		return 0
	}

	return f.SetBytesWide(componentsData[0])
}

// SetRandom sets the receiver from a random source.
func (f *Fp) SetRandom(prng io.Reader) (ok ct.Bool) {
	var data [FpWideBytes]byte
	_, err := io.ReadFull(prng, data[:])
	if err != nil {
		return 0
	}

	return f.SetBytesWide(data[:])
}

// ComponentsBytes returns component byte slices.
func (f *Fp) ComponentsBytes() [][]byte {
	return [][]byte{f.Bytes()}
}

// Degree returns the extension degree.
func (*Fp) Degree() uint64 {
	return 1
}

// SetLimbs sets the receiver from limbs.
func (f *Fp) SetLimbs(data []uint64) (ok ct.Bool) {
	if len(data) != 4 {
		return 0
	}

	var byteData [FpBytes]byte
	binary.LittleEndian.PutUint64(byteData[:8], data[0])
	binary.LittleEndian.PutUint64(byteData[8:16], data[1])
	binary.LittleEndian.PutUint64(byteData[16:24], data[2])
	binary.LittleEndian.PutUint64(byteData[24:], data[3])

	return f.SetBytes(byteData[:])
}

// SetBytes sets the receiver from bytes.
func (f *Fp) SetBytes(data []byte) (ok ct.Bool) {
	if len(data) != int(FpBytes) || (data[FpBytes-1]&0x80 != 0) {
		return 0
	}

	fiatFpFromBytes(&f.v, (*[FpBytes]uint8)(data))
	return 1
}

// SetBytesWide sets the receiver from wide bytes.
func (f *Fp) SetBytesWide(data []byte) (ok ct.Bool) {
	if len(data) > FpWideBytes {
		return 0
	}

	var wideData [FpWideBytes]byte
	copy(wideData[:], data[:])
	p255 := ct.Choice(wideData[FpBytes-1] >> 7)
	wideData[FpBytes-1] &= 0x7f
	p511 := ct.Choice(wideData[FpWideBytes-1] >> 7)
	wideData[FpWideBytes-1] &= 0x7f

	var zero, lo, hi, twoTo256, pLo, pHi Fp
	zero.SetZero()
	twoTo256.SetUint64(19 * 2)
	okLo := lo.SetBytes(wideData[:FpBytes])
	okHi := hi.SetBytes(wideData[FpBytes:])
	hi.Mul(&hi, &twoTo256)
	ok = okLo & okHi
	pLo.SetUint64(19)
	pLo.Select(p255, &zero, &pLo)
	lo.Add(&lo, &pLo)
	pHi.SetUint64(19 * 19 * 2)
	pHi.Select(p511, &zero, &pHi)
	hi.Add(&hi, &pHi)

	var out Fp
	out.Add(&lo, &hi)
	f.Select(ok, f, &out)
	return ok
}

// Bytes returns the canonical byte encoding.
func (f *Fp) Bytes() []byte {
	var data [FpBytes]byte
	fiatFpToBytes(&data, &f.v)
	return data[:]
}

// Limbs returns the little-endian limb representation.
func (f *Fp) Limbs() []uint64 {
	var limbs [4]uint64
	data := f.Bytes()
	limbs[0] = binary.LittleEndian.Uint64(data[0:8])
	limbs[1] = binary.LittleEndian.Uint64(data[8:16])
	limbs[2] = binary.LittleEndian.Uint64(data[16:24])
	limbs[3] = binary.LittleEndian.Uint64(data[24:32])
	return limbs[:]
}

// MustSetHex sets the receiver from a hex string, panicking on failure.
func (f *Fp) MustSetHex(data string) {
	dataBytes, err := hex.DecodeString(data)
	if err != nil {
		panic(err)
	}
	slices.Reverse(dataBytes)

	ok := f.SetBytes(dataBytes)
	if ok != 1 {
		panic("cannot set bytes")
	}
}

// String returns the string form of the receiver.
func (f *Fp) String() string {
	fBytes := f.Bytes()
	slices.Reverse(fBytes)
	fBi := new(big.Int).SetBytes(fBytes)
	return fBi.String()
}

// GoString returns the Go-syntax representation of the receiver.
func (f *Fp) GoString() string {
	fBytes := f.Bytes()
	slices.Reverse(fBytes)
	return "0x" + hex.EncodeToString(f.Bytes())
}

func anyNonZero(data *[FpBytes]byte) (ok ct.Bool) {
	v := uint64(
		data[0] | data[1] | data[2] | data[3] | data[4] | data[5] | data[6] | data[7] |
			data[8] | data[9] | data[10] | data[11] | data[12] | data[13] | data[14] | data[15] |
			data[16] | data[17] | data[18] | data[19] | data[20] | data[21] | data[22] | data[23] |
			data[24] | data[25] | data[26] | data[27] | data[28] | data[29] | data[30] | data[31])

	return ct.Bool((v | -v) >> 63)
}
