package commitments

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/errs-go/errs"
)

func Commit[K CommitmentKey[K, M, W, C], M Message, W Witness, C Commitment[C]](key K, message M, prng io.Reader) (C, W, error) {
	if utils.IsNil(key) || utils.IsNil(message) || prng == nil {
		return *new(C), *new(W), ErrIsNil.WithMessage("key, message, and prng must not be nil")
	}
	witness, err := key.SampleWitness(prng)
	if err != nil {
		return *new(C), *new(W), errs.Wrap(err).WithMessage("could not sample witness")
	}
	commitment, err := key.CommitWithWitness(message, witness)
	if err != nil {
		return *new(C), *new(W), errs.Wrap(err).WithMessage("could not compute commitment")
	}
	return commitment, witness, nil
}

func ReRandomise[K HomomorphicCommitmentKey[K, M, W, C, S], M Message, W Witness, C Commitment[C], S any](key K, commitment C, prng io.Reader) (C, W, error) {
	if utils.IsNil(key) || utils.IsNil(commitment) || prng == nil {
		return *new(C), *new(W), ErrIsNil.WithMessage("key, commitment, and prng must not be nil")
	}
	witness, err := key.SampleWitness(prng)
	if err != nil {
		return *new(C), *new(W), errs.Wrap(err).WithMessage("could not sample witness")
	}
	newCommitment, err := key.ReRandomise(commitment, witness)
	if err != nil {
		return *new(C), *new(W), errs.Wrap(err).WithMessage("could not compute commitment")
	}
	return newCommitment, witness, nil
}
