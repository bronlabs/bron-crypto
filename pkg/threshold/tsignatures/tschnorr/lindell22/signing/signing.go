package signing

import (
	"sort"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22"
)

func BigS(participants ds.Set[types.IdentityKey]) []byte {
	sortedIdentities := types.ByPublicKey(participants.List())
	sort.Sort(sortedIdentities)
	var bigS []byte
	for _, identity := range sortedIdentities {
		pid := identity.PublicKey().ToAffineCompressed()
		bigS = append(bigS, pid...)
	}

	return bigS
}

func Aggregate[F schnorr.Variant[F]](variant schnorr.Variant[F], partialSignatures ...*lindell22.PartialSignature) (signature *schnorr.Signature[F], err error) {
	if len(partialSignatures) < 2 {
		return nil, errs.NewFailed("not enough partial signatures")
	}

	e := partialSignatures[0].E
	r := partialSignatures[0].R.Curve().Identity()
	s := partialSignatures[0].S.ScalarField().Zero()
	for _, partialSignature := range partialSignatures {
		if !e.Equal(partialSignature.E) {
			return nil, errs.NewFailed("invalid partial signature")
		}

		// step 1: r <- Σ ri
		r = r.Add(partialSignature.R)

		// step 2: s <- Σ si
		s = s.Add(partialSignature.S)
	}

	return &schnorr.Signature[F]{
		Variant: variant,
		E:       e,
		R:       r,
		S:       s,
	}, nil
}
