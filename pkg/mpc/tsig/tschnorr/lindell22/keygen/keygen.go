package keygen

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/interactive/dkg/gennaro"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig/tschnorr"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig/tschnorr/lindell22"
	"github.com/bronlabs/errs-go/errs"
)

// DKGOutput is the output of a distributed key generation protocol.
type DKGOutput[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S]] = gennaro.DKGOutput[GE, S]

// NewShard creates a threshold Schnorr shard from DKG output.
func NewShard[
	GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S],
](
	output *gennaro.DKGOutput[GE, S],
) (*lindell22.Shard[GE, S], error) {
	shard, err := tschnorr.NewShard(
		output.Share(),
		output.VerificationVector(),
		output.AccessStructure(),
	)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create tSchnorr shard from DKG output")
	}
	return shard, nil
}
