package uints

import (
	"encoding/binary"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/cronokirby/saferith"
	"math/bits"
)

var (
	_ algebra.UintLike[U128] = U128{}
)

type U128 [2]uint64

func NewU128FromBytes(data []byte) (z U128, err error) {
	if len(data) > 16 {
		return U128{}, errs.NewFailed("data is too long")
	}

	var zBytes [16]byte
	copy(zBytes[16-len(data):], data)
	z[1], z[0] = binary.BigEndian.Uint64(zBytes[0:8]), binary.BigEndian.Uint64(zBytes[8:16])
	return z, nil
}

func (x U128) Add(y U128) (z U128) {
	var c uint64
	z[0], c = bits.Add64(x[0], y[0], 0)
	z[1] = x[1] + y[1] + c
	return z
}

func (x U128) Sub(y U128) (z U128) {
	var b uint64
	z[0], b = bits.Sub64(x[0], y[0], 0)
	z[1] = x[1] - y[1] - b
	return z
}

func (x U128) Neg() (z U128) {
	c := uint64(1)
	z[0], c = bits.Add64(^x[0], 0, c)
	z[1] = ^x[1] + c
	return z
}

func (x U128) Mul(y U128) (z U128) {
	var c uint64
	c, z[0] = bits.Mul64(x[0], y[0])
	z[1] = c + x[0]*y[1] + x[1]*y[0]
	return z
}

func (x U128) Square() (z U128) {
	var c uint64
	z01 := x[0] * x[1]
	c, z[0] = bits.Mul64(x[0], x[0])
	z[1] = c + z01 + z01
	return z
}

func (x U128) Bytes() (data [16]byte) {
	binary.BigEndian.PutUint64(data[0:8], x[1])
	binary.BigEndian.PutUint64(data[8:16], x[0])
	return data
}

func (x U128) Clone() (z U128) {
	return x
}

func (x U128) Equal(y U128) bool {
	neq := (x[0] ^ y[0]) | (x[1] ^ y[1])
	return neq == 0
}

func (x U128) IsOne() bool {
	neq := (x[0] ^ uint64(1)) | (x[1] ^ 0)
	return neq == 0
}

func (x U128) IsZero() bool {
	neq := x[0] | x[1]
	return neq == 0
}

func (x U128) HashCode() uint64 {
	return x[0] ^ x[1]
}

func (x U128) Structure() algebra.Structure[U128] {
	//TODO implement me
	panic("implement me")
}

func (x U128) MarshalBinary() (data []byte, err error) {
	xBytes := x.Bytes()
	return xBytes[:], nil
}

func (x U128) UnmarshalBinary(data []byte) error {
	panic("impossible to implement")
}

func (x U128) Op(y U128) U128 {
	return x.Add(y)
}

func (x U128) OtherOp(y U128) U128 {
	return x.Mul(y)
}

func (x U128) Double() U128 {
	return x.Add(x)
}

func (x U128) IsOpIdentity() bool {
	return x.IsZero()
}

func (x U128) TryOpInv() (U128, error) {
	return x.Neg(), nil
}

func (x U128) TryInv() (U128, error) {
	//TODO implement me
	panic("implement me")
}

func (x U128) TryDiv(y U128) (U128, error) {
	//TODO implement me
	panic("implement me")
}

func (x U128) TryNeg() (U128, error) {
	return x.Neg(), nil
}

func (x U128) TrySub(y U128) (U128, error) {
	return x.Sub(y), nil
}

func (x U128) OpInv() U128 {
	return x.Neg()
}

func (x U128) IsLessThanOrEqual(y U128) bool {
	return ct.SliceGreaterLE(y[:], x[:]) != 0
}

func (x U128) Nat() *saferith.Nat {
	xBytes := x.Bytes()
	return new(saferith.Nat).SetBytes(xBytes[:])
}
