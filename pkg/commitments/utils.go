package commitments

import (
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/utils"
)

// Commit samples a fresh witness from key and returns the commitment to message
// together with that witness. It is the standard way to commit: hiding relies on
// the witness being freshly drawn from prng, so prng must be a cryptographically
// secure source. The returned witness is the opening and must be kept secret until
// the commitment is revealed.
func Commit[K CommitmentKey[K, M, W, C], M Message, W Witness, C Commitment[C]](key K, message M, prng io.Reader) (commitment C, witness W, err error) {
	if utils.IsNil(key) || utils.IsNil(message) || prng == nil {
		return *new(C), *new(W), ErrIsNil.WithMessage("key, message, and prng must not be nil")
	}
	witness, err = key.SampleWitness(prng)
	if err != nil {
		return *new(C), *new(W), errs.Wrap(err).WithMessage("could not sample witness")
	}
	commitment, err = key.CommitWithWitness(message, witness)
	if err != nil {
		return *new(C), *new(W), errs.Wrap(err).WithMessage("could not compute commitment")
	}
	return commitment, witness, nil
}

// ReRandomise samples a fresh witness shift and blinds commitment with it, yielding
// an unlinkable commitment to the same message. It returns the new commitment and
// the sampled SHIFT — not the full opening: to open newCommitment, combine the
// original witness with this shift via key.WitnessOp. prng must be cryptographically
// secure, since unlinkability depends on the shift being fresh and secret.
func ReRandomise[K HomomorphicCommitmentKey[K, M, W, C, S], M Message, W Witness, C Commitment[C], S any](key K, commitment C, prng io.Reader) (newCommitment C, witness W, err error) {
	if utils.IsNil(key) || utils.IsNil(commitment) || prng == nil {
		return *new(C), *new(W), ErrIsNil.WithMessage("key, commitment, and prng must not be nil")
	}
	witness, err = key.SampleWitness(prng)
	if err != nil {
		return *new(C), *new(W), errs.Wrap(err).WithMessage("could not sample witness")
	}
	newCommitment, err = key.ReRandomise(commitment, witness)
	if err != nil {
		return *new(C), *new(W), errs.Wrap(err).WithMessage("could not compute commitment")
	}
	return newCommitment, witness, nil
}
