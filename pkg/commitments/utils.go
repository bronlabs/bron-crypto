package commitments

import "github.com/bronlabs/bron-crypto/pkg/base/errs"

func NewGenericVerifier[T Committer[W, M, C], W Witness, M Message, C Commitment](committer T, commitmentsAreEqual func(c1, c2 C) bool) *GenericVerifier[T, W, M, C] {
	return &GenericVerifier[T, W, M, C]{committer: committer, commitmentsAreEqual: commitmentsAreEqual}
}

type GenericVerifier[T Committer[W, M, C], W Witness, M Message, C Commitment] struct {
	committer           T
	commitmentsAreEqual func(c1, c2 C) bool
}

func (v *GenericVerifier[T, W, M, C]) Verify(commitment C, message M, witness W) error {
	recomputed, err := v.committer.CommitWithWitness(message, witness)
	if err != nil {
		return errs.WrapFailed(err, "cannot recompute commitment")
	}
	if !v.commitmentsAreEqual(recomputed, commitment) {
		return errs.NewValue("commitment does not match")
	}
	return nil
}
