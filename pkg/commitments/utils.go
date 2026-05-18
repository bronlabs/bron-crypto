package commitments

import (
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
)

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

func ReRandomise[
	K GroupHomomorphicCommitmentKey[K, M, MG, MV, W, WG, WV, C, CG, CV, S],
	M interface {
		Message
		base.Transparent[MV]
	}, MG algebra.Group[MV], MV algebra.GroupElement[MV],
	W interface {
		Witness
		base.Transparent[WV]
	}, WG algebra.Group[WV], WV algebra.GroupElement[WV],
	C interface {
		Commitment[C]
		base.Transparent[CV]
	}, CG algebra.FiniteGroup[CV], CV algebra.GroupElement[CV],
	S any,
](key K, commitment C, prng io.Reader) (newCommitment C, witness W, err error) {
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
