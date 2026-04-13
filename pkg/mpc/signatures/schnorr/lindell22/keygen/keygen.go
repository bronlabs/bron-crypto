package keygen

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/mpc"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/schnorr"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/schnorr/lindell22"
	"github.com/bronlabs/errs-go/errs"
)

// NewShard creates a Schnorr shard from a base shard output by the DKG protocol.
func NewShard[
	GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S],
](
	output *mpc.BaseShard[GE, S],
) (*lindell22.Shard[GE, S], error) {
	shard, err := schnorr.NewShard(
		output.Share(),
		output.VerificationVector(),
		output.MSP(),
	)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create tSchnorr shard from base shard")
	}
	return shard, nil
}
