package hashcommitment

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
	_ commitments.Opening    = Opening(nil)
	_ commitments.Commitment = Commitment(nil)

	_ commitments.Scheme[Commitment, Message, Opening] = (*Scheme)(nil)
)

type Message = [][]byte
type Opening = []byte
type Commitment = []byte

type Scheme struct {
	crs []byte
}

func NewScheme(crs []byte) *Scheme {
	return &Scheme{
		crs: crs,
	}
}

func (s *Scheme) RandomOpening(prng io.Reader) (Opening, error) {
	var witness [base.CollisionResistanceBytes]byte
	_, err := io.ReadFull(prng, witness[:])
	if err != nil {
		return nil, errs.WrapRandomSample(err, "cannot sample opening")
	}

	return witness[:], nil
}

func (s *Scheme) CommitWithOpening(message Message, witness Opening) (Commitment, error) {
	commitment, err := hashing.KmacPrefixedLength(witness, s.crs, sha3.NewCShake128, message...)
	if err != nil {
		return nil, errs.WrapHashing(err, "cannot compute digest")
	}
	return commitment, nil
}

func (s *Scheme) Commit(message Message, prng io.Reader) (Commitment, Opening, error) {
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

func (s *Scheme) Verify(message Message, commitment Commitment, witness Opening) error {
	rhs, err := s.CommitWithOpening(message, witness)
	if err != nil {
		return errs.WrapVerification(err, "verification failed")
	}
	if !s.IsEqual(commitment, rhs) {
		return errs.NewVerification("verification failed")
	}

	return nil
}

func (s *Scheme) IsEqual(lhs, rhs Commitment) bool {
	return slices.Equal(lhs, rhs)
}
