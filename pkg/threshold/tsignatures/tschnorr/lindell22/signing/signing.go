package signing

import (
	"sort"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	schnorr "github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr/vanilla"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22"
)

func BigS(participants ds.HashSet[types.IdentityKey]) []byte {
	sortedIdentities := types.ByPublicKey(participants.List())
	sort.Sort(sortedIdentities)
	var bigS []byte
	for _, identity := range sortedIdentities {
		pid := identity.PublicKey().ToAffineCompressed()
		bigS = append(bigS, pid...)
	}

	return bigS
}

func Aggregate(partialSignatures ...*lindell22.PartialSignature) (signature *schnorr.Signature, err error) {
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

		// compute Rsum
		r = r.Add(partialSignature.R)

		// compute Ssum
		s = s.Add(partialSignature.S)
	}

	// return (Rsum, Ssum) as signature
	return &schnorr.Signature{
		E: e,
		R: r,
		S: s,
	}, nil
}
