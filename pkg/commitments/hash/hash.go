package hashcommitments

import (
	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
	"golang.org/x/crypto/sha3"
	"io"
	"slices"
)

var (
	_ commitments.Message    = Message(nil)
	_ commitments.Witness    = Witness(nil)
	_ commitments.Commitment = Commitment(nil)

	_ commitments.Scheme[Commitment, Message, Witness] = (*Scheme)(nil)
)

type Message = [][]byte
type Witness = []byte
type Commitment = []byte

type Scheme struct {
	crs []byte
}

func NewScheme(crs []byte) *Scheme {
	return &Scheme{
		crs: crs,
	}
}

func (s *Scheme) RandomWitness(prng io.Reader) Witness {
	var witness [base.CollisionResistanceBytes]byte
	_, err := io.ReadFull(prng, witness[:])
	if err != nil {
		panic(err)
	}

	return witness[:]
}

func (s *Scheme) CommitWithWitness(message Message, witness Witness) Commitment {
	commitment, err := hashing.KmacPrefixedLength(witness, s.crs, sha3.NewCShake128, message...)
	if err != nil {
		panic(err)
	}
	return commitment
}

func (s *Scheme) Commit(message Message, prng io.Reader) (Commitment, Witness) {
	witness := s.RandomWitness(prng)
	return s.CommitWithWitness(message, witness), witness
}

func (s *Scheme) Verify(message Message, commitment Commitment, witness Witness) error {
	rhs := s.CommitWithWitness(message, witness)
	if s.IsEqual(commitment, rhs) {
		return nil
	}

	return errs.NewVerification("verification failed")
}

func (s *Scheme) IsEqual(lhs, rhs Commitment) bool {
	return slices.Equal(lhs, rhs)
}
