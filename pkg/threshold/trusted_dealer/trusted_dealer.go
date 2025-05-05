package trusted_dealer

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	feldman_vss "github.com/bronlabs/bron-crypto/pkg/threshold/sharing/feldman"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures"
)

func Deal[
	C curves.Curve[P, F, S], P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](protocol types.ThresholdProtocol[C, P, F, S], secret S, prng io.Reader) (sks datastructures.Map[types.IdentityKey, *tsignatures.SigningKeyShare[C, P, F, S]], ppk datastructures.Map[types.IdentityKey, *tsignatures.PartialPublicKeys[C, P, F, S]], err error) {
	//if secret == nil || prng == nil {
	//	return nil, nil, errs.NewValidation("secret or prng is nil")
	//}
	//if err := types.ValidateThresholdProtocolConfig(protocol); err != nil {
	//	return nil, nil, errs.WrapValidation(err, "could not validate protocol config")
	//}

	feldmanDealer, err := feldman_vss.NewScheme(protocol.Threshold(), protocol.TotalParties(), protocol.Curve())
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot create Feldman-VSS dealer")
	}
	shares, verification, err := feldmanDealer.DealVerifiable(secret, prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot deal shares")
	}

	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	publicShares := hashmap.NewComparableHashMap[types.SharingID, P]()
	for sharingId := range sharingConfig.Iter() {
		publicShares.Put(sharingId, polynomials.EvalInExponent(verification, types.SharingIDToScalar(sharingId, protocol.Curve().ScalarField())))
	}

	sks = hashmap.NewHashableHashMap[types.IdentityKey, *tsignatures.SigningKeyShare[C, P, F, S]]()
	for sharingId, identityKey := range sharingConfig.Iter() {
		sks.Put(identityKey, &tsignatures.SigningKeyShare[C, P, F, S]{
			Share:     shares[sharingId].Value,
			PublicKey: verification[0],
		})
	}

	ppk = hashmap.NewHashableHashMap[types.IdentityKey, *tsignatures.PartialPublicKeys[C, P, F, S]]()
	for _, identityKey := range sharingConfig.Iter() {
		ppk.Put(identityKey, &tsignatures.PartialPublicKeys[C, P, F, S]{
			PublicKey:               verification[0],
			Shares:                  publicShares,
			FeldmanCommitmentVector: verification,
		})
	}

	return sks, ppk, nil
}
