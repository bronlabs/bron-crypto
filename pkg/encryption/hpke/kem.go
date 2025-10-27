package hpke

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
	"github.com/bronlabs/bron-crypto/pkg/encryption/hpke/internal"
)

func WithSenderPrivateKey[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](sk *PrivateKey[S]) encryption.KEMOption[*KEM[P, B, S], *PublicKey[P, B, S], *Capsule[P, B, S]] {
	return func(kem *KEM[P, B, S]) error {
		kem.senderPrivateKey = sk
		return nil
	}
}

type KEM[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	v                *internal.DHKEMScheme[P, B, S]
	senderPrivateKey *PrivateKey[S]
}

func (k *KEM[P, B, S]) Encapsulate(receiver *PublicKey[P, B, S], prng io.Reader) (*encryption.SymmetricKey, *Capsule[P, B, S], error) {
	var kv []byte
	var ephemeralPublicKey *PublicKey[P, B, S]
	var err error
	if k.IsAuthenticated() {
		kv, ephemeralPublicKey, err = k.v.AuthEncap(receiver, k.senderPrivateKey, prng)
	} else {
		kv, ephemeralPublicKey, err = k.v.Encap(receiver, prng)
	}
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not encapsulate")
	}
	out, err := encryption.NewSymmetricKey(kv)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not create symmetric key")
	}
	return out, ephemeralPublicKey, nil
}

func (k *KEM[P, B, S]) IsAuthenticated() bool {
	return k.senderPrivateKey != nil
}

func WithSenderPublicKey[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](pk *PublicKey[P, B, S]) encryption.DEMOption[*DEM[P, B, S], *Capsule[P, B, S]] {
	return func(dem *DEM[P, B, S]) error {
		dem.senderPublicKey = pk
		return nil
	}
}

type DEM[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	v                  *internal.DHKEMScheme[P, B, S]
	receiverPrivateKey *PrivateKey[S]
	senderPublicKey    *PublicKey[P, B, S]
}

func (d *DEM[P, B, S]) Decapsulate(capsule *Capsule[P, B, S]) (*encryption.SymmetricKey, error) {
	var kv []byte
	var err error
	if d.IsAuthenticated() {
		kv, err = d.v.AuthDecap(d.receiverPrivateKey, d.senderPublicKey, capsule)
	} else {
		kv, err = d.v.Decap(d.receiverPrivateKey, capsule)
	}
	if err != nil {
		return nil, errs.WrapFailed(err, "could not decapsulate")
	}
	out, err := encryption.NewSymmetricKey(kv)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create symmetric key")
	}
	return out, nil
}

func (d *DEM[P, B, S]) IsAuthenticated() bool {
	return d.senderPublicKey != nil
}
