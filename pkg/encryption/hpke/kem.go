package hpke

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
	"github.com/bronlabs/bron-crypto/pkg/encryption/hpke/internal"
	"github.com/bronlabs/errs-go/errs"
)

// WithSenderPrivateKey returns an option that enables authenticated encapsulation
// by providing the sender's private key. When set, the KEM uses AuthEncap instead
// of Encap, allowing the receiver to verify the sender's identity.
//
// See: https://www.rfc-editor.org/rfc/rfc9180.html#section-4.1
func WithSenderPrivateKey[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](sk *PrivateKey[S]) encryption.KEMOption[*KEM[P, B, S], *PublicKey[P, B, S], *Capsule[P, B, S]] {
	return func(kem *KEM[P, B, S]) error {
		kem.senderPrivateKey = sk
		return nil
	}
}

// KEM provides key encapsulation mechanism operations for HPKE.
// It wraps the underlying DHKEM (Diffie-Hellman based KEM) and supports both
// standard and authenticated encapsulation.
//
// The KEM generates an ephemeral key pair and combines it with the receiver's
// public key to produce a shared secret and a capsule (the ephemeral public key).
//
// See: https://www.rfc-editor.org/rfc/rfc9180.html#section-4
type KEM[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	v                *internal.DHKEMScheme[P, B, S]
	senderPrivateKey *PrivateKey[S]
}

// Encapsulate generates a shared secret and encapsulates it for the given receiver.
// Returns:
//   - A symmetric key derived from the shared secret
//   - A capsule (ephemeral public key) to send to the receiver
//
// If WithSenderPrivateKey was configured, this performs authenticated encapsulation
// (AuthEncap), otherwise standard encapsulation (Encap).
//
// See: https://www.rfc-editor.org/rfc/rfc9180.html#section-4.1
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
		return nil, nil, errs.Wrap(err)
	}
	out, err := encryption.NewSymmetricKey(kv)
	if err != nil {
		return nil, nil, errs.Wrap(err)
	}
	return out, ephemeralPublicKey, nil
}

// IsAuthenticated returns true if the sender's private key has been configured,
// indicating that authenticated encapsulation will be used.
func (k *KEM[P, B, S]) IsAuthenticated() bool {
	return k.senderPrivateKey != nil
}

// WithSenderPublicKey returns an option that enables authenticated decapsulation
// by providing the sender's public key. When set, the DEM uses AuthDecap instead
// of Decap, verifying that the capsule was created by the sender.
//
// See: https://www.rfc-editor.org/rfc/rfc9180.html#section-4.1
func WithSenderPublicKey[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](pk *PublicKey[P, B, S]) encryption.DEMOption[*DEM[P, B, S], *Capsule[P, B, S]] {
	return func(dem *DEM[P, B, S]) error {
		dem.senderPublicKey = pk
		return nil
	}
}

// DEM provides data encapsulation mechanism (decapsulation) operations for HPKE.
// It uses the receiver's private key to recover the shared secret from a capsule.
//
// The DEM supports both standard and authenticated decapsulation. Authenticated
// decapsulation verifies that the shared secret was produced using the sender's
// private key.
//
// See: https://www.rfc-editor.org/rfc/rfc9180.html#section-4
type DEM[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	v                  *internal.DHKEMScheme[P, B, S]
	receiverPrivateKey *PrivateKey[S]
	senderPublicKey    *PublicKey[P, B, S]
}

// Decapsulate recovers the shared secret from a capsule using the receiver's private key.
// Returns a symmetric key derived from the shared secret.
//
// If WithSenderPublicKey was configured, this performs authenticated decapsulation
// (AuthDecap), otherwise standard decapsulation (Decap).
//
// See: https://www.rfc-editor.org/rfc/rfc9180.html#section-4.1
func (d *DEM[P, B, S]) Decapsulate(capsule *Capsule[P, B, S]) (*encryption.SymmetricKey, error) {
	var kv []byte
	var err error
	if d.IsAuthenticated() {
		kv, err = d.v.AuthDecap(d.receiverPrivateKey, d.senderPublicKey, capsule)
	} else {
		kv, err = d.v.Decap(d.receiverPrivateKey, capsule)
	}
	if err != nil {
		return nil, errs.Wrap(err)
	}
	out, err := encryption.NewSymmetricKey(kv)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return out, nil
}

// IsAuthenticated returns true if the sender's public key has been configured,
// indicating that authenticated decapsulation will be used.
func (d *DEM[P, B, S]) IsAuthenticated() bool {
	return d.senderPublicKey != nil
}
