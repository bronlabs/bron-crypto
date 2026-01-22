package keygen

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/errs-go/pkg/errs"
	"github.com/bronlabs/bron-crypto/pkg/signatures/bls"
	"github.com/bronlabs/bron-crypto/pkg/threshold/dkg/gennaro"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tbls"
)

// DKGOutput is an alias for gennaro.DKGOutput, representing the output of a
// distributed key generation protocol suitable for creating Boldyreva threshold BLS shards.
type DKGOutput[
	PK curves.PairingFriendlyPoint[PK, PKFE, SG, SGFE, E, S], PKFE algebra.FieldElement[PKFE],
	SG curves.PairingFriendlyPoint[SG, SGFE, PK, PKFE, E, S], SGFE algebra.FieldElement[SGFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
] = gennaro.DKGOutput[PK, S]

// NewShortKeyShard creates a threshold BLS shard for the short key variant from DKG output.
// In the short key variant, public keys are in G1 (smaller) and signatures are in G2 (larger).
// Returns an error if the DKG output is invalid or shard creation fails.
func NewShortKeyShard[
	PK curves.PairingFriendlyPoint[PK, PKFE, SG, SGFE, E, S], PKFE algebra.FieldElement[PKFE],
	SG curves.PairingFriendlyPoint[SG, SGFE, PK, PKFE, E, S], SGFE algebra.FieldElement[SGFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
](
	output *gennaro.DKGOutput[PK, S],
) (*tbls.Shard[PK, PKFE, SG, SGFE, E, S], error) {
	pk, err := bls.NewPublicKey(output.PublicKeyValue())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create BLS public key")
	}
	shard, err := tbls.NewShortKeyShard(output.Share(), pk, output.VerificationVector(), output.AccessStructure())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create tBLS short key shard")
	}
	return shard, nil
}

// NewLongKeyShard creates a threshold BLS shard for the long key variant from DKG output.
// In the long key variant, public keys are in G2 (larger) and signatures are in G1 (smaller).
// Returns an error if the DKG output is invalid or shard creation fails.
func NewLongKeyShard[
	PK curves.PairingFriendlyPoint[PK, PKFE, SG, SGFE, E, S], PKFE algebra.FieldElement[PKFE],
	SG curves.PairingFriendlyPoint[SG, SGFE, PK, PKFE, E, S], SGFE algebra.FieldElement[SGFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
](
	output *gennaro.DKGOutput[PK, S],
) (*tbls.Shard[PK, PKFE, SG, SGFE, E, S], error) {
	pk, err := bls.NewPublicKey(output.PublicKeyValue())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create BLS public key")
	}
	shard, err := tbls.NewLongKeyShard(output.Share(), pk, output.VerificationVector(), output.AccessStructure())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create tBLS long key shard")
	}
	return shard, nil
}
