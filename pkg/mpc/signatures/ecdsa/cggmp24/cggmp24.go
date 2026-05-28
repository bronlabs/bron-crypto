package cggmp24

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/commitments/intcom"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/mpc"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	sigecdsa "github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

// AuxInfo holds auxiliary information for the CGGMP24 signature scheme.
// TODO: make members "private" and add getters
type AuxInfo struct {
	PaillierSecretKey  *paillier.SecretKey
	PaillierPublicKeys map[sharing.ID]*paillier.PublicKey

	RingPedersenSecretKey  *intcom.TrapdoorKey
	RingPedersenPublicKeys map[sharing.ID]*intcom.CommitmentKey
}

type Shard[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	mpc.BaseShard[P, S]

	auxInfo *AuxInfo
}

// NewShard returns a new shard.
// TODO: add validation to auxInfo
func NewShard[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](baseShard *mpc.BaseShard[P, S], info *AuxInfo) (*Shard[P, B, S], error) {
	if baseShard == nil {
		return nil, ErrNil.WithMessage("base shard")
	}

	sh := &Shard[P, B, S]{
		BaseShard: *baseShard,
		auxInfo:   info,
	}
	return sh, nil
}

// PublicKey returns the public key.
func (sh *Shard[P, B, S]) PublicKey() *sigecdsa.PublicKey[P, B, S] {
	pkValue := sh.PublicKeyValue()
	pk, err := sigecdsa.NewPublicKey(pkValue)
	if err != nil {
		panic(err) // this should never happen.
	}
	return pk
}

// AuxInfo returns the auxiliary information.
func (sh *Shard[P, B, S]) AuxInfo() *AuxInfo {
	return sh.auxInfo
}

// Equal returns true if the two shards are equal.
// TODO: add comparison for auxInfo
func (sh *Shard[P, B, S]) Equal(rhs *Shard[P, B, S]) bool {
	return sh.BaseShard.Equal(&rhs.BaseShard)
}
