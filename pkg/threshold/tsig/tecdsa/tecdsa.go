package tecdsa

import (
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/feldman"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig"
)

type PublicMaterial[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	tsig.BasePublicMaterial[P, S]
	pk     *ecdsa.PublicKey[P, B, S]
	pkOnce sync.Once
}

func (pm *PublicMaterial[P, B, S]) PublicKey() *ecdsa.PublicKey[P, B, S] {
	pm.pkOnce.Do(func() {
		var err error
		pm.pk, err = ecdsa.NewPublicKey(pm.BasePublicMaterial.PublicKey())
		if err != nil {
			panic(err)
		}
	})
	return pm.pk
}

type Shard[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	tsig.BaseShard[P, S]
	pk     *ecdsa.PublicKey[P, B, S]
	pkOnce sync.Once
}

func (sh *Shard[P, B, S]) PublicKeyMaterial() *PublicMaterial[P, B, S] {
	return &PublicMaterial[P, B, S]{
		BasePublicMaterial: sh.BasePublicMaterial,
		pk:                 sh.pk,
	}
}

func (sh *Shard[P, B, S]) PublicKey() *ecdsa.PublicKey[P, B, S] {
	sh.pkOnce.Do(func() {
		var err error
		sh.pk, err = ecdsa.NewPublicKey(sh.BaseShard.PublicKey())
		if err != nil {
			panic(err)
		}
	})
	return sh.pk
}

func (sh *Shard[P, B, S]) Equal(other tsig.Shard[*ecdsa.PublicKey[P, B, S], *feldman.Share[S], *feldman.AccessStructure]) bool {
	o, ok := other.(*Shard[P, B, S])
	return ok && sh.BaseShard.Equal(&o.BaseShard)
}

func NewShard[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](
	share *feldman.Share[S],
	fv feldman.VerificationVector[P, S],
	accessStructure *feldman.AccessStructure,
) (*Shard[P, B, S], error) {
	if share == nil || fv == nil || accessStructure == nil {
		return nil, errs.NewIsNil("nil input parameters")
	}
	bs, err := tsig.NewBaseShard(share, fv, accessStructure)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create base shard")
	}
	pk, err := ecdsa.NewPublicKey(fv.Coefficients()[0])
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create public key from verification vector")
	}
	return &Shard[P, B, S]{BaseShard: *bs, pk: pk}, nil
}
