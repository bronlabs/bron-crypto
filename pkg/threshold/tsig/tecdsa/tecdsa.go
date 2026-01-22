package tecdsa

import (
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/feldman"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig"
	"github.com/bronlabs/errs-go/pkg/errs"
)

// PublicMaterial holds public key material.
type PublicMaterial[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	tsig.BasePublicMaterial[P, S]

	pk     *ecdsa.PublicKey[P, B, S]
	pkOnce sync.Once
}

// PublicKey returns the public key.
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

// Shard holds a tECDSA key share.
type Shard[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	tsig.BaseShard[P, S]

	pk     *ecdsa.PublicKey[P, B, S]
	pkOnce sync.Once
}

// PublicKeyMaterial returns the public key material.
func (sh *Shard[P, B, S]) PublicKeyMaterial() *PublicMaterial[P, B, S] {
	//nolint:exhaustruct // lazy initialisation
	return &PublicMaterial[P, B, S]{
		BasePublicMaterial: sh.BasePublicMaterial,
		pk:                 sh.pk,
	}
}

// PublicKey returns the public key.
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

// Equal reports whether the value equals other.
func (sh *Shard[P, B, S]) Equal(other tsig.Shard[*ecdsa.PublicKey[P, B, S], *feldman.Share[S], *sharing.ThresholdAccessStructure]) bool {
	o, ok := other.(*Shard[P, B, S])
	return ok && sh.BaseShard.Equal(&o.BaseShard)
}

// NewShard returns a new shard.
func NewShard[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](
	share *feldman.Share[S],
	fv feldman.VerificationVector[P, S],
	accessStructure *sharing.ThresholdAccessStructure,
) (*Shard[P, B, S], error) {
	if share == nil || fv == nil || accessStructure == nil {
		return nil, ErrNil.WithMessage("nil input parameters")
	}
	bs, err := tsig.NewBaseShard(share, fv, accessStructure)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create base shard")
	}
	pk, err := ecdsa.NewPublicKey(fv.Coefficients()[0])
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create public key from verification vector")
	}

	//nolint:exhaustruct // lazy initialisation
	return &Shard[P, B, S]{BaseShard: *bs, pk: pk}, nil
}
