package keygen

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike"
	"github.com/bronlabs/bron-crypto/pkg/threshold/dkg/gennaro"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tschnorr"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tschnorr/lindell22"
)

type DKGOutput[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S]] = gennaro.DKGOutput[GE, S]

func NewShard[
	GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S],
](
	output *gennaro.DKGOutput[GE, S],
) (*lindell22.Shard[GE, S], error) {
	pk, err := schnorrlike.NewPublicKey(output.PublicKeyValue())
	if err != nil {
		return nil, err
	}
	return tschnorr.NewShard(
		output.Share(),
		pk,
		output.VerificationVector(),
		output.AccessStructure(),
	)
}
