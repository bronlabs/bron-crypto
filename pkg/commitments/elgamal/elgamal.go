package elgamalcommitment

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	"io"
)

var (
	_ commitments.Message    = Message(nil)
	_ commitments.Opening    = Opening(nil)
	_ commitments.Scalar     = Scalar(nil)
	_ commitments.Commitment = (*Commitment)(nil)

	_ commitments.HomomorphicScheme[*Commitment, Message, Opening, Scalar] = (*Scheme)(nil)
)

type Message PlainText
type Opening Nonce
type Scalar curves.Scalar
type Commitment = CipherText

type Scheme struct {
	pk *PublicKey
}

func NewScheme(pk *PublicKey) *Scheme {
	return &Scheme{
		pk: pk,
	}
}

func (s *Scheme) RandomOpening(prng io.Reader) (Opening, error) {
	witness, err := s.pk.H.Curve().ScalarField().Random(prng)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "cannot sample opening")
	}
	return witness, nil
}

func (s *Scheme) CommitWithOpening(message Message, witness Opening) (*Commitment, error) {
	return EncryptWithNonce(s.pk, message, witness), nil
}

func (s *Scheme) Commit(message Message, prng io.Reader) (*Commitment, Opening, error) {
	witness, err := s.RandomOpening(prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "cannot sample opening")
	}
	return EncryptWithNonce(s.pk, message, witness), witness, nil
}

func (s *Scheme) Verify(message Message, commitment *Commitment, witness Opening) error {
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

	return lhs.C1.Equal(rhs.C1) && lhs.C2.Equal(rhs.C2)
}

func (s *Scheme) CommitmentSum(x *Commitment, ys ...*Commitment) *Commitment {
	sum := &Commitment{
		C1: x.C1.Clone(),
		C2: x.C2.Clone(),
	}

	for _, y := range ys {
		sum = s.CommitmentAdd(sum, y)
	}
	return sum
}

func (*Scheme) CommitmentAdd(x, y *Commitment) *Commitment {
	return &Commitment{
		C1: x.C1.Add(y.C1),
		C2: x.C2.Add(y.C2),
	}
}

func (*Scheme) CommitmentSub(x, y *Commitment) *Commitment {
	return &Commitment{
		C1: x.C1.Sub(y.C1),
		C2: x.C2.Sub(y.C2),
	}
}

func (*Scheme) CommitmentNeg(x *Commitment) *Commitment {
	return &Commitment{
		C1: x.C1.Neg(),
		C2: x.C2.Neg(),
	}
}

func (*Scheme) CommitmentScale(x *Commitment, sc Scalar) *Commitment {
	return &Commitment{
		C1: x.C1.ScalarMul(sc),
		C2: x.C2.ScalarMul(sc),
	}
}

func (s *Scheme) OpeningSum(x Opening, ys ...Opening) Opening {
	sum := x.Clone()
	for _, y := range ys {
		sum = s.OpeningAdd(sum, y)
	}
	return sum
}

func (*Scheme) OpeningAdd(x, y Opening) Opening {
	return x.Add(y)
}

func (*Scheme) OpeningSub(x, y Opening) Opening {
	return x.Sub(y)
}

func (*Scheme) OpeningNeg(x Opening) Opening {
	return x.Neg()
}

func (*Scheme) OpeningScale(x Opening, sc Scalar) Opening {
	return x.Mul(sc)
}
