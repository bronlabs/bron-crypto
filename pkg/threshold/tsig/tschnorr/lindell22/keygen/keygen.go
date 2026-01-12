package keygen

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/threshold/dkg/gennaro"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tschnorr"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tschnorr/lindell22"
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
		return nil, errs2.Wrap(err).WithMessage("failed to create tSchnorr shard from DKG output")
	}
	return shard, nil
}
