package internal

import (
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	"github.com/bronlabs/errs-go/errs"
)

// GenericOpen is used in the implementation of CommitmentKey.Open.
func GenericOpen[K commitments.CommitmentKey[K, M, W, C], M commitments.Message, W commitments.Witness, C commitments.Commitment[C]](key K, commitment C, message M, witness W) error {
	if utils.IsNil(key) || utils.IsNil(commitment) || utils.IsNil(message) || utils.IsNil(witness) {
		return commitments.ErrIsNil.WithMessage("key, commitment, message, and witness must not be nil")
	}
	recomputed, err := key.CommitWithWitness(message, witness)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot recompute commitment")
	}
	if !recomputed.Equal(commitment) {
		return commitments.ErrVerificationFailed.WithMessage("commitment does not match")
	}
	return nil
}
