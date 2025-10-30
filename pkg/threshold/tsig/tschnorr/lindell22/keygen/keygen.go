package keygen

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
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
	// pk, err := schnorrlike.NewPublicKey(output.PublicKeyValue())
	// if err != nil {
	// 	return nil, errs.WrapFailed(err, "failed to create public key from DKG output")
	// }
	shard, err := tschnorr.NewShard(
		output.Share(),
		output.VerificationVector(),
		output.AccessStructure(),
	)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create tSchnorr shard from DKG output")
	}
	return shard, nil
}
