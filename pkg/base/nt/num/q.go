package num

import (
	"encoding/binary"
	"io"
	"math/big"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/crtp"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/cronokirby/saferith"
)

const (
	Name = "Q"
)

var (
	qInstance = &Rationals{}

	_ algebra.Field[*Rat]        = (*Rationals)(nil)
	_ algebra.FieldElement[*Rat] = (*Rat)(nil)
)

type Rationals struct{}

func (q *Rationals) New(n *Int, d *NatPlus) (*Rat, error) {
	if n == nil || d == nil {
		return nil, errs.NewIsNil("n or d is nil")
	}
	return &Rat{n, d}, nil
}

func (q *Rationals) FromInt64(value int64) *Rat {
	n := Z().FromInt64(value)
	d := NPlus().One()
	return &Rat{n, d}
}

func (q *Rationals) FromUint64(value uint64) *Rat {
	n := Z().FromUint64(value)
	d := NPlus().One()
	return &Rat{n, d}
}

func (q *Rationals) FromInt(value *Int) (*Rat, error) {
	if value == nil {
		return nil, errs.NewIsNil("value")
	}
	return &Rat{n: value, d: NPlus().One()}, nil
}

func (q *Rationals) FromNat(value *Nat) (*Rat, error) {
	if value == nil {
		return nil, errs.NewIsNil("value")
	}
	return &Rat{n: value.Lift(), d: NPlus().One()}, nil
}

func (q *Rationals) FromNatPlus(value *NatPlus) (*Rat, error) {
	if value == nil {
		return nil, errs.NewIsNil("value")
	}
	return &Rat{n: value.Lift(), d: NPlus().One()}, nil
}

func (q *Rationals) FromBigRat(value *big.Rat) (*Rat, error) {
	if value == nil {
		return nil, errs.NewIsNil("value")
	}
	n, err := Z().FromBig(value.Num())
	if err != nil {
		return nil, errs.WrapFailed(err, "could not convert big.Int to Int")
	}
	d, err := NPlus().FromBig(value.Denom())
	if err != nil {
		return nil, errs.WrapFailed(err, "could not convert big.Int to NatPlus")
	}
	return &Rat{n, d}, nil
}

func (q *Rationals) RandomRange(l, h *Rat, prng io.Reader) (*Rat, error) {
	if l == nil || h == nil || prng == nil {
		return nil, errs.NewIsNil("l, h or prng is nil")
	}
	if h.IsLessThanOrEqual(l) {
		return nil, errs.NewFailed("empty range")
	}

	d := l.d.Mul(h.d)
	ln := l.n.Mul(h.d.Lift())
	hn := h.n.Mul(l.d.Lift())
	n, err := Z().Random(ln, hn, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not generate random number")
	}
	return &Rat{n, d}, nil
}

func (q *Rationals) RandomRangeInt(l, h *Rat, prng io.Reader) (*Int, error) {
	randomQ, err := q.RandomRange(l, h, prng)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "failed to sample random element in Q")
	}
	randomZ, _, err := randomQ.n.EuclideanDiv(randomQ.d.Lift())
	if err != nil {
		return nil, errs.WrapRandomSample(err, "failed to sample random element in Z")
	}
	return randomZ, nil
}

func (q *Rationals) Name() string {
	return Name
}

func (q *Rationals) Order() cardinal.Cardinal {
	return cardinal.Infinite()
}

func (q *Rationals) FromBytes(data []byte) (*Rat, error) {
	panic("not implemented (yet?)")
}

func (q *Rationals) ElementSize() int {
	panic("not implemented for infinite domains")
}

func (q *Rationals) Characteristic() cardinal.Cardinal {
	return cardinal.Zero()
}

func (q *Rationals) OpIdentity() *Rat {
	return q.Zero()
}

func (q *Rationals) One() *Rat {
	return &Rat{
		n: Z().One(),
		d: NPlus().One(),
	}
}

func (q *Rationals) Zero() *Rat {
	return &Rat{
		n: Z().Zero(),
		d: NPlus().One(),
	}
}

func (q *Rationals) IsSemiDomain() bool {
	return true
}

func (q *Rationals) ExtensionDegree() uint {
	return 1
}

func Q() *Rationals {
	return qInstance
}

type Rat struct {
	n *Int
	d *NatPlus
}

func (r *Rat) Structure() crtp.Structure[*Rat] {
	return Q()
}

func (r *Rat) Bytes() []byte {
	// this never return error
	nBytes, _ := ((*saferith.Int)(r.n.v)).MarshalBinary()
	dBytes := ((*saferith.Nat)(r.d.v)).Bytes()
	return slices.Concat(binary.BigEndian.AppendUint64(nil, uint64(len(nBytes))), nBytes, dBytes)
}

func (r *Rat) Clone() *Rat {
	return &Rat{
		n: r.n.Clone(),
		d: r.d.Clone(),
	}
}

func (r *Rat) Equal(rhs *Rat) bool {
	if r == nil || rhs == nil {
		return r == rhs
	}
	rd := r.d.Lift()
	rhsD := rhs.d.Lift()

	return r.n.Mul(rhsD).Equal(rhs.n.Mul(rd))
}

func (r *Rat) HashCode() base.HashCode {
	// We have to normalize to be consistent with Equal
	rNormalized := r.Normalize()
	return rNormalized.n.HashCode() ^ rNormalized.d.HashCode()
}

func (r *Rat) String() string {
	return r.n.String() + "/" + r.d.String()
}

func (r *Rat) Op(e *Rat) *Rat {
	return r.Add(e)
}

func (r *Rat) OtherOp(e *Rat) *Rat {
	return r.Mul(e)
}

func (r *Rat) Add(e *Rat) *Rat {
	rn := r.n.Mul(e.d.Lift())
	en := e.n.Mul(r.d.Lift())
	n := rn.Add(en)
	d := r.d.Mul(e.d)

	return &Rat{n, d}
}

func (r *Rat) Double() *Rat {
	return &Rat{r.n.Double(), r.d}
}

func (r *Rat) Mul(e *Rat) *Rat {
	n := r.n.Mul(e.n)
	d := r.d.Mul(e.d)

	return &Rat{n, d}
}

func (r *Rat) Square() *Rat {
	n := r.n.Square()
	d := r.d.Square()

	return &Rat{n, d}
}

func (r *Rat) IsOpIdentity() bool {
	return r.IsZero()
}

func (r *Rat) TryOpInv() (*Rat, error) {
	return r.Neg(), nil
}

func (r *Rat) IsOne() bool {
	return r.n.Equal(r.d.Lift())
}

func (r *Rat) TryInv() (*Rat, error) {
	if r.n.IsZero() {
		return nil, errs.NewIsZero("division by zero")
	}

	neg := r.n.IsNegative()
	// this never returns error
	d, _ := NPlus().FromNat(r.n.Abs())
	n := r.d.Lift()
	if neg {
		n = n.Neg()
	}
	return &Rat{n, d}, nil
}

func (r *Rat) TryDiv(rhs *Rat) (*Rat, error) {
	rhsInv, err := rhs.TryInv()
	if err != nil {
		return nil, errs.WrapIsZero(err, "division by zero")
	}
	return r.Mul(rhsInv), nil
}

func (r *Rat) IsZero() bool {
	return r.n.IsZero()
}

func (r *Rat) TryNeg() (*Rat, error) {
	return r.Neg(), nil
}

func (r *Rat) TrySub(e *Rat) (*Rat, error) {
	return r.Sub(e), nil
}

func (r *Rat) OpInv() *Rat {
	return r.Neg()
}

func (r *Rat) Neg() *Rat {
	n := r.n.Neg()
	d := r.d

	return &Rat{n, d}
}

func (r *Rat) Sub(e *Rat) *Rat {
	return r.Add(e.Neg())
}

func (r *Rat) IsProbablyPrime() bool {
	return false
}

func (r *Rat) EuclideanDiv(rhs *Rat) (quot, rem *Rat, err error) {
	//TODO implement me
	panic("implement me")
}

func (r *Rat) EuclideanValuation() *Rat {
	//TODO implement me
	panic("implement me")
}

func (r *Rat) Normalize() *Rat {
	rnBig := r.n.Big()
	rdBig := r.d.Big()
	g := new(big.Int).GCD(nil, nil, rnBig, rdBig)
	nBig := new(big.Int).Div(rnBig, g)
	dBig := new(big.Int).Div(rdBig, g)

	// never returns error
	n, _ := Z().FromBig(nBig)
	d, _ := NPlus().FromBig(dBig)
	return &Rat{n, d}
}

func (r *Rat) Numerator() *Int {
	return r.n
}

func (r *Rat) Denominator() *NatPlus {
	return r.d
}

func (r *Rat) IsNegative() bool {
	return r.n.IsNegative()
}

func (r *Rat) IsPositive() bool {
	return r.n.IsPositive()
}

func (r *Rat) IsInt() bool {
	return r.Normalize().d.IsOne()
}

func (r *Rat) IsLessThanOrEqual(e *Rat) bool {
	lhs := r.n.Mul(e.d.Lift())
	rhs := e.n.Mul(r.d.Lift())
	return lhs.IsLessThanOrEqual(rhs)
}
