package keygen

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/signatures/bls"
	"github.com/bronlabs/bron-crypto/pkg/threshold/dkg/gennaro"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tbls"
)

type DKGOutput[
	PK curves.PairingFriendlyPoint[PK, PKFE, SG, SGFE, E, S], PKFE algebra.FieldElement[PKFE],
	SG curves.PairingFriendlyPoint[SG, SGFE, PK, PKFE, E, S], SGFE algebra.FieldElement[SGFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
] = gennaro.DKGOutput[PK, S]

func NewShortKeyShard[
	PK curves.PairingFriendlyPoint[PK, PKFE, SG, SGFE, E, S], PKFE algebra.FieldElement[PKFE],
	SG curves.PairingFriendlyPoint[SG, SGFE, PK, PKFE, E, S], SGFE algebra.FieldElement[SGFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
](
	output *gennaro.DKGOutput[PK, S],
) (*tbls.Shard[PK, PKFE, SG, SGFE, E, S], error) {
	pk, err := bls.NewPublicKey(output.PublicKeyValue())
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create BLS public key")
	}
	shard, err := tbls.NewShortKeyShard(output.Share(), pk, output.VerificationVector(), output.AccessStructure())
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create tBLS short key shard")
	}
	return shard, nil
}

func NewLongKeyShard[
	PK curves.PairingFriendlyPoint[PK, PKFE, SG, SGFE, E, S], PKFE algebra.FieldElement[PKFE],
	SG curves.PairingFriendlyPoint[SG, SGFE, PK, PKFE, E, S], SGFE algebra.FieldElement[SGFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
](
	output *gennaro.DKGOutput[PK, S],
) (*tbls.Shard[PK, PKFE, SG, SGFE, E, S], error) {
	pk, err := bls.NewPublicKey(output.PublicKeyValue())
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create BLS public key")
	}
	shard, err := tbls.NewLongKeyShard(output.Share(), pk, output.VerificationVector(), output.AccessStructure())
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create tBLS long key shard")
	}
	return shard, nil
}
