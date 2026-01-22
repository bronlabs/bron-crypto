package bls12381

import (
	"encoding"
	"encoding/hex"
	"hash/fnv"
	"io"
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	bls12381Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/errs-go/errs"
)

const (
	// GtName is the target group name.
	GtName = "BLS12381Fp12Mul"
)

var (
	_ algebra.MultiplicativeGroup[*GtElement]        = (*Gt)(nil)
	_ algebra.MultiplicativeGroupElement[*GtElement] = (*GtElement)(nil)
	_ encoding.BinaryMarshaler                       = (*GtElement)(nil)
	_ encoding.BinaryUnmarshaler                     = (*GtElement)(nil)

	gtInstance *Gt
	gtInitOnce sync.Once
)

// Gt represents the BLS12-381 GT group.
type Gt struct{}

// NewGt returns the BLS12-381 GT group instance.
func NewGt() *Gt {
	gtInitOnce.Do(func() {
		gtInstance = &Gt{}
	})
	return gtInstance
}

// Name returns the name of the structure.
func (*Gt) Name() string {
	return GtName
}

// ElementSize returns the element size in bytes.
func (*Gt) ElementSize() int {
	return 96
}

// Order returns the group or field order.
func (*Gt) Order() cardinal.Cardinal {
	// GT has the same order as the scalar field (r)
	return NewScalarField().Order()
}

// Hash maps input bytes to an element or point.
func (*Gt) Hash(bytes []byte) (*GtElement, error) {
	return nil, curves.ErrFailed.WithMessage("Hashing not implemented for Gt")
}

// Random samples a random element.
func (*Gt) Random(prng io.Reader) (*GtElement, error) {
	return nil, curves.ErrFailed.WithMessage("Random sampling not implemented for Gt")
}

// One returns the multiplicative identity.
func (*Gt) One() *GtElement {
	var one GtElement
	one.V.SetOne()
	return &one
}

// OpIdentity returns the group identity.
func (g *Gt) OpIdentity() *GtElement {
	return g.One()
}

// FromBytes decodes an element from bytes.
func (*Gt) FromBytes(inBytes []byte) (*GtElement, error) {
	if len(inBytes) != 96 {
		return nil, curves.ErrInvalidLength.WithMessage("input must be 96 bytes long")
	}

	var element GtElement
	if ok := element.V.SetUniformBytes(inBytes); ok == 0 {
		return nil, curves.ErrFailed.WithMessage("failed to set bytes")
	}

	return &element, nil
}

// GtElement represents an element of the target group.
type GtElement struct {
	V bls12381Impl.Gt
}

// Clone returns a copy of the element.
func (ge *GtElement) Clone() *GtElement {
	var clone GtElement
	clone.V.Set(&ge.V.Fp12)
	return &clone
}

// Equal reports whether the receiver equals v.
func (ge *GtElement) Equal(rhs *GtElement) bool {
	return ge.V.Equal(&rhs.V.Fp12) == 1
}

// HashCode returns a hash code for the receiver.
func (ge *GtElement) HashCode() base.HashCode {
	h := fnv.New64a()
	_, _ = h.Write(ge.V.Bytes())
	return base.HashCode(h.Sum64())
}

// Bytes returns the canonical byte encoding.
func (ge *GtElement) Bytes() []byte {
	return ge.V.Bytes()
}

// Structure returns the algebraic structure for the receiver.
func (*GtElement) Structure() algebra.Structure[*GtElement] {
	return NewGt()
}

// Mul sets the receiver to lhs * rhs.
func (ge *GtElement) Mul(e *GtElement) *GtElement {
	var product GtElement
	product.V.Mul(&ge.V.Fp12, &e.V.Fp12)
	return &product
}

// Square sets the receiver to v^2.
func (ge *GtElement) Square() *GtElement {
	var square GtElement
	square.V.Square(&ge.V.Fp12)
	return &square
}

// IsOne reports whether the receiver is one.
func (ge *GtElement) IsOne() bool {
	return ge.V.IsOne() == 1
}

// Inv sets the receiver to the inverse of a, if it exists.
func (ge *GtElement) Inv() *GtElement {
	var inv GtElement
	_ = inv.V.Inv(&ge.V.Fp12)
	return &inv
}

// Div sets the receiver to lhs / rhs, if rhs is nonzero.
func (ge *GtElement) Div(e *GtElement) *GtElement {
	var quotient GtElement
	_ = quotient.V.Div(&ge.V.Fp12, &e.V.Fp12)
	return &quotient
}

// TryInv returns the multiplicative inverse.
func (ge *GtElement) TryInv() (*GtElement, error) {
	return ge.Inv(), nil
}

// TryDiv divides by the given element.
func (ge *GtElement) TryDiv(e *GtElement) (*GtElement, error) {
	return ge.Div(e), nil
}

// Op applies the group operation.
func (ge *GtElement) Op(e *GtElement) *GtElement {
	return ge.Mul(e)
}

// IsOpIdentity reports whether the element is the identity.
func (ge *GtElement) IsOpIdentity() bool {
	return ge.IsOne()
}

// TryOpInv returns the group inverse.
func (ge *GtElement) TryOpInv() (*GtElement, error) {
	return ge.OpInv(), nil
}

// OpInv returns the group inverse.
func (ge *GtElement) OpInv() *GtElement {
	return ge.Inv()
}

// String returns the string form of the receiver.
func (ge *GtElement) String() string {
	return "0x" + hex.EncodeToString(ge.V.Bytes())
}

// MarshalBinary implements encoding.BinaryMarshaler.
func (ge *GtElement) MarshalBinary() ([]byte, error) {
	return ge.Bytes(), nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (ge *GtElement) UnmarshalBinary(data []byte) error {
	pp, err := NewGt().FromBytes(data)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot decode element")
	}
	ge.V.Set(&pp.V.Fp12)
	return nil
}
