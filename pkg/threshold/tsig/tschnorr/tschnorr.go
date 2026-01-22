package tschnorr

import (
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/signatures"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/additive"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/feldman"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig"
	"github.com/bronlabs/errs-go/pkg/errs"
)

// MPCFriendlyVariant extends schnorrlike.Variant with methods needed for threshold signing.
// It provides parity correction for secret shares and nonces required by some Schnorr variants.
type MPCFriendlyVariant[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S], M schnorrlike.Message] interface {
	schnorrlike.Variant[GE, S, M]
	CorrectAdditiveSecretShareParity(publicKey *schnorrlike.PublicKey[GE, S], share *additive.Share[S]) (*additive.Share[S], error)
	CorrectPartialNonceParity(aggregatedNonceCommitment GE, nonce S) (GE, S, error)
}

// MPCFriendlyScheme extends schnorrlike.Scheme with threshold signing capabilities.
// It provides a partial signature verifier for validating individual party contributions.
type MPCFriendlyScheme[
	VR MPCFriendlyVariant[GE, S, M],
	GE algebra.PrimeGroupElement[GE, S],
	S algebra.PrimeFieldElement[S],
	M schnorrlike.Message,
	KG signatures.KeyGenerator[*schnorrlike.PrivateKey[GE, S], *schnorrlike.PublicKey[GE, S]],
	SG schnorrlike.Signer[VR, GE, S, M],
	VF schnorrlike.Verifier[VR, GE, S, M],
] interface {
	schnorrlike.Scheme[VR, GE, S, M, KG, SG, VF]
	PartialSignatureVerifier(
		fullPublicKey *schnorrlike.PublicKey[GE, S],
		opts ...signatures.VerifierOption[VF, *schnorrlike.PublicKey[GE, S], M, *schnorrlike.Signature[GE, S]],
	) (schnorrlike.Verifier[VR, GE, S, M], error) // making batch verification etc is not objective here, so won't return VF
}

// PartialSignature represents a party's contribution to a threshold Schnorr signature.
type PartialSignature[
	GE algebra.PrimeGroupElement[GE, S],
	S algebra.PrimeFieldElement[S],
] struct {
	Sig schnorrlike.Signature[GE, S]
}

// AsSchnorrSignature returns the underlying Schnorr signature.
func (ps *PartialSignature[GE, S]) AsSchnorrSignature() *schnorrlike.Signature[GE, S] {
	if ps == nil {
		return nil
	}
	return &ps.Sig
}

// Bytes serialises the partial signature to a byte slice.
func (ps *PartialSignature[E, S]) Bytes() []byte {
	if ps == nil {
		return nil
	}
	out := ps.Sig.S.Bytes()
	out = append(out, ps.Sig.R.Bytes()...)
	out = append(out, ps.Sig.E.Bytes()...)
	return out
}

// PublicMaterial contains public information for threshold Schnorr signature verification.
type PublicMaterial[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	tsig.BasePublicMaterial[E, S]

	pk     *schnorrlike.PublicKey[E, S]
	pkOnce sync.Once
}

// PublicKey returns the threshold public key as a schnorrlike.PublicKey.
func (pm *PublicMaterial[E, S]) PublicKey() *schnorrlike.PublicKey[E, S] {
	pm.pkOnce.Do(func() {
		var err error
		pm.pk, err = schnorrlike.NewPublicKey(pm.BasePublicMaterial.PublicKey())
		if err != nil {
			panic(err)
		}
	})
	return pm.pk
}

// Shard represents a party's secret key share for threshold Schnorr signing.
type Shard[
	E algebra.PrimeGroupElement[E, S],
	S algebra.PrimeFieldElement[S],
] struct {
	tsig.BaseShard[E, S]

	pk     *schnorrlike.PublicKey[E, S]
	pkOnce sync.Once
}

// PublicKeyMaterial returns the public material derived from this shard.
func (sh *Shard[E, S]) PublicKeyMaterial() *PublicMaterial[E, S] {
	return &PublicMaterial[E, S]{
		BasePublicMaterial: sh.BasePublicMaterial,
		pk:                 sh.pk,
		pkOnce:             sync.Once{},
	}
}

// PublicKey returns the threshold public key as a schnorrlike.PublicKey.
func (sh *Shard[E, S]) PublicKey() *schnorrlike.PublicKey[E, S] {
	sh.pkOnce.Do(func() {
		var err error
		sh.pk, err = schnorrlike.NewPublicKey(sh.BaseShard.PublicKey())
		if err != nil {
			panic(err)
		}
	})
	return sh.pk
}

// Equal returns true if this shard equals another shard.
func (sh *Shard[E, S]) Equal(other tsig.Shard[*schnorrlike.PublicKey[E, S], *feldman.Share[S], *sharing.ThresholdAccessStructure]) bool {
	o, ok := other.(*Shard[E, S])
	return ok && sh.BaseShard.Equal(&o.BaseShard)
}

// AsSchnorrPrivateKey converts the shard to a schnorrlike.PrivateKey for single-party operations.
func (sh *Shard[E, S]) AsSchnorrPrivateKey() (*schnorrlike.PrivateKey[E, S], error) {
	if sh == nil || sh.Share() == nil {
		return nil, ErrInvalidArgument.WithMessage("shard or share is nil")
	}
	sk, err := schnorrlike.NewPrivateKey(sh.Share().Value(), sh.PublicKey())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create schnorr private key from share")
	}
	return sk, nil
}

// NewShard creates a new threshold Schnorr shard from a Feldman share, verification vector, and access structure.
func NewShard[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](
	share *feldman.Share[S],
	fv feldman.VerificationVector[E, S],
	accessStructure *sharing.ThresholdAccessStructure,
) (*Shard[E, S], error) {
	if share == nil || fv == nil || accessStructure == nil {
		return nil, ErrInvalidArgument.WithMessage("nil input parameters")
	}
	bs, err := tsig.NewBaseShard(share, fv, accessStructure)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create base shard")
	}
	pk, err := schnorrlike.NewPublicKey(fv.Coefficients()[0])
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create public key from verification vector")
	}
	return &Shard[E, S]{BaseShard: *bs, pk: pk, pkOnce: sync.Once{}}, nil
}

var (
	ErrInvalidArgument = errs.New("invalid argument")
)
