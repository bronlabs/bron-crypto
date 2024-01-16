package dkg

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
)

func ConstructPublicKeySharesMap(cohort *integration.CohortConfig, commitmentVectors map[int][]curves.Point, sharingIdToIdentityKey map[int]integration.IdentityKey) (map[types.IdentityHash]curves.Point, error) {
	shares := map[types.IdentityHash]curves.Point{}
	for j, identityKey := range sharingIdToIdentityKey {
		Y_j := cohort.CipherSuite.Curve.Identity()
		for _, C_l := range commitmentVectors {
			jToKs := make([]curves.Scalar, cohort.Protocol.Threshold)
			// TODO: add simultaneous scalar exp
			for k := 0; k < cohort.Protocol.Threshold; k++ {
				exp := cohort.CipherSuite.Curve.ScalarField().New(uint64(k))
				jToK := cohort.CipherSuite.Curve.ScalarField().New(uint64(j)).Exp(exp)
				jToKs[k] = jToK
			}
			jkC_lk, err := cohort.CipherSuite.Curve.MultiScalarMult(jToKs, C_l)
			if err != nil {
				return nil, errs.NewFailed("couldn't derive partial public key share")
			}
			Y_j = Y_j.Add(jkC_lk)
		}
		if Y_j.IsIdentity() {
			return nil, errs.NewIsIdentity("public key share of sharing id %d is at infinity", j)
		}
		shares[identityKey.Hash()] = Y_j
	}
	return shares, nil
}
