package elgamalcommitment

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	"io"
)

var (
	_ commitments.Message    = Message(nil)
	_ commitments.Witness    = Witness(nil)
	_ commitments.Scalar     = Scalar(nil)
	_ commitments.Commitment = (*Commitment)(nil)

	_ commitments.HomomorphicScheme[*Commitment, Message, Witness, Scalar] = (*Scheme)(nil)
)

type Message PlainText
type Witness Nonce
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

func (s *Scheme) RandomWitness(prng io.Reader) Witness {
	witness, err := s.pk.H.Curve().ScalarField().Random(prng)
	if err != nil {
		panic(err)
	}
	return witness
}

func (s *Scheme) CommitWithWitness(message Message, witness Witness) *Commitment {
	return EncryptWithNonce(s.pk, message, witness)
}

func (s *Scheme) Commit(message Message, prng io.Reader) (*Commitment, Witness) {
	witness := s.RandomWitness(prng)
	return EncryptWithNonce(s.pk, message, witness), witness
}

func (s *Scheme) Verify(message Message, commitment *Commitment, witness Witness) error {
	if message == nil || commitment == nil || witness == nil {
		return errs.NewVerification("verification failed")
	}
	rhs := s.CommitWithWitness(message, witness)
	if s.IsEqual(commitment, rhs) {
		return nil
	}

	return errs.NewVerification("verification failed")
}

func (s *Scheme) IsEqual(lhs, rhs *Commitment) bool {
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

func (s *Scheme) CommitmentAdd(x, y *Commitment) *Commitment {
	return &Commitment{
		C1: x.C1.Add(y.C1),
		C2: x.C2.Add(y.C2),
	}
}

func (s *Scheme) CommitmentSub(x, y *Commitment) *Commitment {
	return &Commitment{
		C1: x.C1.Sub(y.C1),
		C2: x.C2.Sub(y.C2),
	}
}

func (s *Scheme) CommitmentNeg(x *Commitment) *Commitment {
	return &Commitment{
		C1: x.C1.Neg(),
		C2: x.C2.Neg(),
	}
}

func (s *Scheme) CommitmentScale(x *Commitment, sc Scalar) *Commitment {
	return &Commitment{
		C1: x.C1.ScalarMul(sc),
		C2: x.C2.ScalarMul(sc),
	}
}

func (s *Scheme) WitnessSum(x Witness, ys ...Witness) Witness {
	sum := x.Clone()
	for _, y := range ys {
		sum = s.WitnessAdd(sum, y)
	}
	return sum
}

func (s *Scheme) WitnessAdd(x, y Witness) Witness {
	return x.Add(y)
}

func (s *Scheme) WitnessSub(x, y Witness) Witness {
	return x.Sub(y)
}

func (s *Scheme) WitnessNeg(x Witness) Witness {
	return x.Neg()
}

func (s *Scheme) WitnessScale(x Witness, sc Scalar) Witness {
	return x.Mul(sc)
}
