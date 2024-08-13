package dfcommitment

import (
	crand "crypto/rand"
	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	"github.com/cronokirby/saferith"
	"io"
	"math/big"
)

var (
	_ commitments.Message    = (*Message)(nil)
	_ commitments.Opening    = (*Opening)(nil)
	_ commitments.Scalar     = (*Scalar)(nil)
	_ commitments.Commitment = (*Commitment)(nil)

	_ commitments.HomomorphicScheme[*Commitment, *Message, *Opening, *Scalar] = (*Scheme)(nil)
)

type Message = saferith.Int
type Opening = saferith.Int
type Scalar = saferith.Int
type Commitment = saferith.Nat

type Scheme struct {
	g *saferith.Nat
	h *saferith.Nat
	n *saferith.Modulus
}

func NewScheme(g, h *saferith.Nat, n *saferith.Modulus) *Scheme {
	return &Scheme{
		g: g,
		h: h,
		n: n,
	}
}

func (s *Scheme) RandomOpening(prng io.Reader) (*Opening, error) {
	witnessBound := new(big.Int)
	witnessBound.SetBit(witnessBound, s.n.BitLen()+base.ComputationalSecurity, 1)
	witnessBig, err := crand.Int(prng, witnessBound)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "cannot sample opening")
	}
	witness := new(saferith.Int).SetBig(witnessBig, s.n.BitLen()+base.ComputationalSecurity)
	return witness, nil
}

func (s *Scheme) CommitWithOpening(message *Message, witness *Opening) (*Commitment, error) {
	gm := new(saferith.Nat).ExpI(s.g, message, s.n)
	hr := new(saferith.Nat).ExpI(s.h, witness, s.n)
	c := new(saferith.Nat).ModMul(gm, hr, s.n)
	return c, nil
}

func (s *Scheme) Commit(message *Message, prng io.Reader) (*Commitment, *Opening, error) {
	witness, err := s.RandomOpening(prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "cannot sample opening")
	}
	commitment, err := s.CommitWithOpening(message, witness)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot compute commitment")
	}

	return commitment, witness, nil
}

func (s *Scheme) Verify(message *Message, commitment *Commitment, witness *Opening) error {
	if message == nil || commitment == nil || witness == nil {
		return errs.NewVerification("verification failed")
	}

	rhs, err := s.CommitWithOpening(message, witness)
	if err != nil {
		return errs.WrapVerification(err, "verification failed")
	}
	if !s.IsEqual(commitment, rhs) {
		return errs.NewVerification("verification failed")
	}

	return nil
}

func (*Scheme) IsEqual(lhs, rhs *Commitment) bool {
	if lhs == nil || rhs == nil {
		return lhs == rhs
	}

	return lhs.Eq(rhs) == 1
}

func (s *Scheme) CommitmentSum(x *Commitment, ys ...*Commitment) *Commitment {
	sum := x.Clone()
	for _, y := range ys {
		sum = s.CommitmentAdd(sum, y)
	}
	return sum
}

func (s *Scheme) CommitmentAdd(x, y *Commitment) *Commitment {
	return new(saferith.Nat).ModMul(x, y, s.n)
}

func (s *Scheme) CommitmentSub(x, y *Commitment) *Commitment {
	yInv := new(saferith.Nat).ModInverse(y, s.n)
	return new(saferith.Nat).ModMul(x, yInv, s.n)
}

func (s *Scheme) CommitmentNeg(x *Commitment) *Commitment {
	xInv := new(saferith.Nat).ModInverse(x, s.n)
	return xInv
}

func (s *Scheme) CommitmentScale(x *Commitment, sc *Scalar) *Commitment {
	return new(saferith.Nat).ExpI(x, sc, s.n)
}

func (s *Scheme) OpeningSum(x *Opening, ys ...*Opening) *Opening {
	sum := x.Clone()
	for _, y := range ys {
		sum = s.OpeningAdd(sum, y)
	}
	return sum
}

func (*Scheme) OpeningAdd(x, y *Opening) *Opening {
	return new(saferith.Int).Add(x, y, -1)
}

func (s *Scheme) OpeningSub(x, y *Opening) *Opening {
	return new(saferith.Int).Add(x, s.OpeningNeg(y), -1)
}

func (*Scheme) OpeningNeg(x *Opening) *Opening {
	return new(saferith.Int).SetInt(x).Neg(1)
}

func (*Scheme) OpeningScale(x *Opening, sc *Scalar) *Opening {
	return new(saferith.Int).Mul(x, sc, -1)
}
