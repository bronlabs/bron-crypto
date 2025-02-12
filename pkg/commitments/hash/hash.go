package hash_comm

import (
	"io"
	"slices"

	"golang.org/x/crypto/blake2b"

	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/commitments"
)

var (
	_ commitments.Commitment                                  = Commitment{}
	_ commitments.Message                                     = Message(nil)
	_ commitments.Witness                                     = Witness{}
	_ commitments.CommittingKey[Commitment, Message, Witness] = (*CommittingKey)(nil)
)

type (
	Commitment [32]byte
	Message    []byte
	Witness    [32]byte
)

type CommittingKey struct {
	key [32]byte
}

func NewCommittingKey(key [32]byte) *CommittingKey {
	return &CommittingKey{key: key}
}

func (*CommittingKey) RandomWitness(prng io.Reader) (witness Witness, err error) {
	var r [32]byte
	if _, err = io.ReadFull(prng, r[:]); err != nil {
		return [32]byte{}, errs.WrapRandomSample(err, "cannot sample witness")
	}

	return r, nil
}

func (k *CommittingKey) CommitWithWitness(message Message, witness Witness) (commitment Commitment, err error) {
	c := blake2b.Sum256(slices.Concat(k.key[:], witness[:], message))

	return c, nil
}

func (k *CommittingKey) Commit(message Message, prng io.Reader) (commitment Commitment, witness Witness, err error) {
	r, err := k.RandomWitness(prng)
	if err != nil {
		return Commitment{}, Witness{}, errs.WrapRandomSample(err, "cannot sample witness")
	}

	c, err := k.CommitWithWitness(message, r)
	if err != nil {
		return Commitment{}, Witness{}, errs.WrapFailed(err, "cannot compute commitment")
	}

	return c, r, nil
}

func (k *CommittingKey) Verify(commitment Commitment, message Message, witness Witness) (err error) {
	c, err := k.CommitWithWitness(message, witness)
	if err != nil {
		return errs.WrapVerification(err, "cannot compute commitment")
	}
	if c != commitment {
		return errs.NewVerification("invalid commitment")
	}

	return nil
}
