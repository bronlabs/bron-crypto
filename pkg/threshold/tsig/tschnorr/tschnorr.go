package tschnorr

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/signatures"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/additive"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/feldman"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig"
)

type MPCFriendlyVariant[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S], M schnorrlike.Message] interface {
	schnorrlike.Variant[GE, S, M]
	CorrectAdditiveSecretShareParity(publicKey *schnorrlike.PublicKey[GE, S], share *additive.Share[S]) (*additive.Share[S], error)
	CorrectPartialNonceParity(aggregatedNonceCommitment GE, nonce S) (GE, S, error)
}

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

type PartialSignature[
GE algebra.PrimeGroupElement[GE, S],
S algebra.PrimeFieldElement[S],
] struct {
	Sig schnorrlike.Signature[GE, S]
}

func (ps *PartialSignature[GE, S]) AsSchnorrSignature() *schnorrlike.Signature[GE, S] {
	if ps == nil {
		return nil
	}
	return &ps.Sig
}

func (ps *PartialSignature[E, S]) Bytes() []byte {
	if ps == nil {
		return nil
	}
	out := ps.Sig.S.Bytes()
	out = append(out, ps.Sig.R.Bytes()...)
	out = append(out, ps.Sig.E.Bytes()...)
	return out
}

type PublicMaterial[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	tsig.BasePublicMaterial[E, S]
	pk *schnorrlike.PublicKey[E, S]
}

func (pm *PublicMaterial[E, S]) PublicKey() *schnorrlike.PublicKey[E, S] {
	return pm.pk
}

type Shard[
E algebra.PrimeGroupElement[E, S],
S algebra.PrimeFieldElement[S],
] struct {
	tsig.BaseShard[E, S]
	pk *schnorrlike.PublicKey[E, S]
}

func (sh *Shard[E, S]) PublicKeyMaterial() *PublicMaterial[E, S] {
	return &PublicMaterial[E, S]{
		BasePublicMaterial: sh.BasePublicMaterial,
		pk:                 sh.pk,
	}
}

func (sh *Shard[E, S]) PublicKey() *schnorrlike.PublicKey[E, S] {
	return sh.pk
}

func (sh *Shard[E, S]) Equal(other tsig.Shard[*schnorrlike.PublicKey[E, S], *feldman.Share[S], *feldman.AccessStructure]) bool {
	o, ok := other.(*Shard[E, S])
	return ok && sh.BaseShard.Equal(&o.BaseShard)
}

func (sh *Shard[E, S]) AsSchnorrPrivateKey() (*schnorrlike.PrivateKey[E, S], error) {
	if sh == nil || sh.Share() == nil {
		return nil, errs.NewIsNil("shard or share is nil")
	}
	sk, err := schnorrlike.NewPrivateKey(sh.Share().Value(), sh.PublicKey())
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create schnorr private key from share")
	}
	return sk, nil
}

func NewShard[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](
	share *feldman.Share[S],
	fv feldman.VerificationVector[E, S],
	accessStructure *feldman.AccessStructure,
) (*Shard[E, S], error) {
	if share == nil || fv == nil || accessStructure == nil {
		return nil, errs.NewIsNil("nil input parameters")
	}
	bs, err := tsig.NewBaseShard(share, fv, accessStructure)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create base shard")
	}
	pk, err := schnorrlike.NewPublicKey(fv.Coefficients()[0])
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create public key from verification vector")
	}

	return &Shard[E, S]{BaseShard: *bs, pk: pk}, nil
}
