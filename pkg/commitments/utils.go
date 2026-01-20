package commitments

import (
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
)

var (
	ErrVerificationFailed = errs2.New("verification failed")
)

func NewGenericVerifier[T Committer[W, M, C], W Witness, M Message, C Commitment[C]](committer T) *GenericVerifier[T, W, M, C] {
	return &GenericVerifier[T, W, M, C]{committer: committer}
}

type GenericVerifier[T Committer[W, M, C], W Witness, M Message, C Commitment[C]] struct {
	committer T
}

// Verify verifies correctness of the commitment.
func (v *GenericVerifier[T, W, M, C]) Verify(commitment C, message M, witness W) error {
	recomputed, err := v.committer.CommitWithWitness(message, witness)
	if err != nil {
		return errs2.Wrap(err).WithMessage("cannot recompute commitment")
	}
	if !recomputed.Equal(commitment) {
		return ErrVerificationFailed.WithMessage("commitment does not match")
	}
	return nil
}
