package tecdsa

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/feldman"
)

// TODO: do whatever it needs to be a proper shard
type Shard[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	share *feldman.Share[S]
	pk    P
}

func NewShard[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]](share *feldman.Share[S], pk P) *Shard[P, B, S] {
	return &Shard[P, B, S]{
		share: share,
		pk:    pk,
	}
}

func (s *Shard[P, B, S]) Share() *feldman.Share[S] {
	return s.share
}

func (s *Shard[P, B, S]) PublicKey() P {
	return s.pk
}
