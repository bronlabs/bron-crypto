package dkg

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

func ConstructPublicKeySharesMap(protocol types.ThresholdProtocol, commitmentVectors map[types.SharingID][]curves.Point, sharingConfig types.SharingConfig) (ds.Map[types.IdentityKey, curves.Point], error) {
	shares := hashmap.NewHashableHashMap[types.IdentityKey, curves.Point]()
	for pair := range sharingConfig.Iter() {
		identityKey := pair.Value
		j := pair.Key
		Y_j := protocol.Curve().AdditiveIdentity()
		jToKs := make([]curves.Scalar, protocol.Threshold())
		for k := 0; k < int(protocol.Threshold()); k++ {
			exp := protocol.Curve().ScalarField().New(uint64(k))
			jToK := protocol.Curve().ScalarField().New(uint64(j)).Exp(exp.Nat())
			jToKs[k] = jToK
		}
		for _, C_l := range commitmentVectors {
			jkC_lk, err := protocol.Curve().MultiScalarMult(jToKs, C_l)
			if err != nil {
				return nil, errs.NewFailed("couldn't derive partial public key share")
			}
			Y_j = Y_j.Add(jkC_lk)
		}
		if Y_j.IsAdditiveIdentity() {
			return nil, errs.NewIsIdentity("public key share of sharing id %d is at infinity", j)
		}
		shares.Put(identityKey, Y_j)
	}
	return shares, nil
}
