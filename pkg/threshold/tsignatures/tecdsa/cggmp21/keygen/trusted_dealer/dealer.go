package trusted_dealer

import (
	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
	"github.com/bronlabs/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	"github.com/bronlabs/krypton-primitives/pkg/indcpa/paillier"
	feldman_vss "github.com/bronlabs/krypton-primitives/pkg/threshold/sharing/feldman"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/tsignatures"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/tsignatures/tecdsa/cggmp21"
	"io"
)

func KeyGen(threshold, total uint, curve curves.Curve, prng io.Reader) (shards ds.Map[types.SharingID, *cggmp21.Shard], err error) {
	dealer, err := feldman_vss.NewScheme(threshold, total, curve)
	if err != nil {
		return nil, err
	}

	sk, err := curve.ScalarField().Random(prng)
	if err != nil {
		return nil, err
	}
	pk := curve.ScalarBaseMult(sk)
	shares, feldmanVector, err := dealer.DealVerifiable(sk, prng)
	if err != nil {
		return nil, err
	}

	paillierSecretKeys := hashmap.NewComparableHashMap[types.SharingID, *paillier.SecretKey]()
	paillierPublicKeys := hashmap.NewComparableHashMap[types.SharingID, *paillier.PublicKey]()
	partialPublicKeys := hashmap.NewComparableHashMap[types.SharingID, curves.Point]()
	for sharingId, share := range shares {
		partialPublicKeys.Put(sharingId, curve.ScalarBaseMult(share.Value))
		paillierPk, paillierSk, err := paillier.KeyGen(cggmp21.ParamLogN, prng)
		if err != nil {
			return nil, err
		}
		paillierPublicKeys.Put(sharingId, paillierPk)
		paillierSecretKeys.Put(sharingId, paillierSk)
	}

	shards = hashmap.NewComparableHashMap[types.SharingID, *cggmp21.Shard]()
	for sharingId, share := range shares {
		paillierSk, _ := paillierSecretKeys.Get(sharingId)
		shards.Put(sharingId, &cggmp21.Shard{
			Share: &tsignatures.SigningKeyShare{
				Share:     share.Value,
				PublicKey: pk,
			},
			PaillierSecretKey: paillierSk,
			PublicShares: &tsignatures.PartialPublicKeys{
				PublicKey:               pk,
				Shares:                  partialPublicKeys,
				FeldmanCommitmentVector: feldmanVector,
			},
			PaillierPublicKeys: paillierPublicKeys,
		})
	}

	return shards, nil
}
