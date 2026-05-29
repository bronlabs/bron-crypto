package commitments

import (
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
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

// WitnessScalarOpUnsignedNumeric computes scalar times witness, where scalar is an unsigned numeric. It does so by repeated application of the witness operation, which is efficient for small scalars but may be inefficient for large scalars. If scalar is zero, it returns the witness identity, which is the result of applying the witness operation to a witness and its inverse. If scalar is one, it returns the witness itself.
func WitnessScalarOpUnsignedNumeric[K HomomorphicCommitmentKey[K, M, W, C, S], M Message, W Witness, C Commitment[C], S any](key K, witness W, scalar algebra.UnsignedNumeric) (W, error) {
	if utils.IsNil(key) || utils.IsNil(witness) || scalar == nil {
		return *new(W), ErrIsNil.WithMessage("key, witness, and scalar must not be nil")
	}
	out, err := algebrautils.ScalarOpUnsignedNumeric(key.WitnessOpInv, key.WitnessOp, witness, scalar)
	if err != nil {
		return *new(W), errs.Wrap(err).WithMessage("could not compute scalar times witness")
	}
	return out, nil
}

// WitnessScalarOpSignedNumeric computes scalar times witness, where scalar is a signed numeric. It does so by computing the absolute value of scalar and applying WitnessScalarOpUnsignedNumeric to it, then inverting the result if scalar is negative. If scalar is zero, it returns the witness identity, which is the result of applying the witness operation to a witness and its inverse. If scalar is one, it returns the witness itself. If scalar is negative one, it returns the witness inverse.
func WitnessScalarOpSignedNumeric[K HomomorphicCommitmentKey[K, M, W, C, S], M Message, W Witness, C Commitment[C], S any](key K, witness W, scalar algebra.SignedNumeric) (W, error) {
	if utils.IsNil(key) || utils.IsNil(witness) || scalar == nil {
		return *new(W), ErrIsNil.WithMessage("key, witness, and scalar must not be nil")
	}
	out, err := algebrautils.ScalarOpSignedNumeric(key.WitnessOpInv, key.WitnessOp, witness, scalar)
	if err != nil {
		return *new(W), errs.Wrap(err).WithMessage("could not compute scalar times witness")
	}
	return out, nil
}

func MessageScalarOpUnsignedNumeric[K HomomorphicCommitmentKey[K, M, W, C, S], M Message, W Witness, C Commitment[C], S any](key K, message M, scalar algebra.UnsignedNumeric) (M, error) {
	if utils.IsNil(key) || utils.IsNil(message) || scalar == nil {
		return *new(M), ErrIsNil.WithMessage("key, message, and scalar must not be nil")
	}
	out, err := algebrautils.ScalarOpUnsignedNumeric(key.MessageOpInv, key.MessageOp, message, scalar)
	if err != nil {
		return *new(M), errs.Wrap(err).WithMessage("could not compute scalar times message")
	}
	return out, nil
}

func MessageScalarOpSignedNumeric[K HomomorphicCommitmentKey[K, M, W, C, S], M Message, W Witness, C Commitment[C], S any](key K, message M, scalar algebra.SignedNumeric) (M, error) {
	if utils.IsNil(key) || utils.IsNil(message) || scalar == nil {
		return *new(M), ErrIsNil.WithMessage("key, message, and scalar must not be nil")
	}
	out, err := algebrautils.ScalarOpSignedNumeric(key.MessageOpInv, key.MessageOp, message, scalar)
	if err != nil {
		return *new(M), errs.Wrap(err).WithMessage("could not compute scalar times message")
	}
	return out, nil
}

// CommitmentScalarOpUnsignedNumeric computes scalar times commitment, where scalar is an unsigned numeric. It does so by repeated application of the commitment operation, which is efficient for small scalars but may be inefficient for large scalars. If scalar is zero, it returns the commitment identity, which is the result of applying the commitment operation to a commitment and its inverse. If scalar is one, it returns the commitment itself.
func CommitmentScalarOpUnsignedNumeric[K HomomorphicCommitmentKey[K, M, W, C, S], M Message, W Witness, C Commitment[C], S any](key K, commitment C, scalar algebra.UnsignedNumeric) (C, error) {
	if utils.IsNil(key) || utils.IsNil(commitment) || scalar == nil {
		return *new(C), ErrIsNil.WithMessage("key, commitment, and scalar must not be nil")
	}
	out, err := algebrautils.ScalarOpUnsignedNumeric(key.CommitmentOpInv, key.CommitmentOp, commitment, scalar)
	if err != nil {
		return *new(C), errs.Wrap(err).WithMessage("could not compute scalar times commitment")
	}
	return out, nil
}

// CommitmentScalarOpSignedNumeric computes scalar times commitment, where scalar is a signed numeric. It does so by computing the absolute value of scalar and applying CommitmentScalarOpUnsignedNumeric to it, then inverting the result if scalar is negative. If scalar is zero, it returns the commitment identity, which is the result of applying the commitment operation to a commitment and its inverse. If scalar is one, it returns the commitment itself. If scalar is negative one, it returns the commitment inverse.
func CommitmentScalarOpSignedNumeric[K HomomorphicCommitmentKey[K, M, W, C, S], M Message, W Witness, C Commitment[C], S any](key K, commitment C, scalar algebra.SignedNumeric) (C, error) {
	if utils.IsNil(key) || utils.IsNil(commitment) || scalar == nil {
		return *new(C), ErrIsNil.WithMessage("key, commitment, and scalar must not be nil")
	}
	out, err := algebrautils.ScalarOpSignedNumeric(key.CommitmentOpInv, key.CommitmentOp, commitment, scalar)
	if err != nil {
		return *new(C), errs.Wrap(err).WithMessage("could not compute scalar times commitment")
	}
	return out, nil
}
