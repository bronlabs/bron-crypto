package trusted_dealer

import (
	"crypto/rsa"
	"io"

	"github.com/cronokirby/saferith"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/rep23"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/trsa"
)

func Keygen(protocol types.ThresholdProtocol, prng io.Reader) (shards ds.Map[types.IdentityKey, *trsa.Shard], err error) {
	if prng == nil {
		return nil, errs.NewIsNil("prng")
	}
	if protocol == nil || protocol.Threshold() != 2 || protocol.TotalParties() != 3 {
		return nil, errs.NewValidation("invalid protocol")
	}

	repDealer := rep23.NewIntScheme()

	sk1, err := rsa.GenerateKey(prng, trsa.RsaBitLen/2)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot generate RSA key")
	}
	if sk1.E != trsa.RsaE {
		return nil, errs.NewValidation("wrong RSA E value")
	}
	d1 := new(saferith.Int).SetBig(sk1.D, trsa.RsaBitLen)
	d1Shares, err := repDealer.Deal(d1, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot deal shares")
	}

	sk2, err := rsa.GenerateKey(prng, trsa.RsaBitLen/2)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot generate RSA key")
	}
	if sk2.E != trsa.RsaE {
		return nil, errs.NewValidation("RSA key must have E=65537")
	}
	d2 := new(saferith.Int).SetBig(sk2.D, trsa.RsaBitLen)
	d2Shares, err := repDealer.Deal(d2, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot deal shares")
	}

	var paddingKey [32]byte
	_, err = io.ReadFull(prng, paddingKey[:])
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot read padding key")
	}

	shards = hashmap.NewHashableHashMap[types.IdentityKey, *trsa.Shard]()
	sharingCfg := types.DeriveSharingConfig(protocol.Participants())
	for sharingId, identityKey := range sharingCfg.Iter() {
		d1Share, ok := d1Shares[sharingId]
		if !ok {
			return nil, errs.NewFailed("d share for %d not found", sharingId)
		}
		d2Share, ok := d2Shares[sharingId]
		if !ok {
			return nil, errs.NewFailed("d share for %d not found", sharingId)
		}

		shards.Put(identityKey, &trsa.Shard{
			D1Share:    d1Share,
			D2Share:    d2Share,
			PaddingKey: paddingKey,
			PublicShard: trsa.PublicShard{
				N1: saferith.ModulusFromBytes(sk1.N.Bytes()),
				N2: saferith.ModulusFromBytes(sk2.N.Bytes()),
				E:  trsa.RsaE,
			},
		})
	}

	return shards, nil
}
