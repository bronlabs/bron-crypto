package tschnorr

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/signatures"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorr"
	"github.com/bronlabs/bron-crypto/pkg/threshold/dkg/gennaro"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/additive"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/feldman"
)

type MPCFriendlyVariant[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S], M schnorr.Message] interface {
	schnorr.Variant[GE, S, M]
	// todo: remove additive logic
	DeriveAdditiveSecretShare(shard *Shard[GE, S], ac *sharing.MinimalQualifiedAccessStructure) (*additive.Share[S], error)
	CorrectPartialNonceParity(aggregatedNonceCommitment GE, nonce S) (GE, S, error)
}

type MPCFriendlyScheme[
	VR MPCFriendlyVariant[GE, S, M],
	GE algebra.PrimeGroupElement[GE, S],
	S algebra.PrimeFieldElement[S],
	M schnorr.Message,
	KG signatures.KeyGenerator[*schnorr.PrivateKey[GE, S], *schnorr.PublicKey[GE, S]],
	SG schnorr.Signer[VR, GE, S, M],
	VF schnorr.Verifier[VR, GE, S, M],
] interface {
	schnorr.Scheme[VR, GE, S, M, KG, SG, VF]
	PartialSignatureVerifier(
		fullPublicKey *schnorr.PublicKey[GE, S],
		opts ...signatures.VerifierOption[VF, *schnorr.PublicKey[GE, S], M, *schnorr.Signature[GE, S]],
	) (schnorr.Verifier[VR, GE, S, M], error) // making batch verification etc is not objective here, so won't return VF
}

type PartialSignature[
	GE algebra.PrimeGroupElement[GE, S],
	S algebra.PrimeFieldElement[S],
] struct {
	Sig schnorr.Signature[GE, S]
}

func (ps *PartialSignature[GE, S]) AsSchnorrSignature() *schnorr.Signature[GE, S] {
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
	publicKey         *schnorr.PublicKey[E, S]
	accessStructure   *feldman.AccessStructure
	fv                feldman.VerificationVector[E, S]
	partialPublicKeys ds.Map[sharing.ID, *schnorr.PublicKey[E, S]]
}

func (spm *PublicMaterial[E, S]) PublicKey() *schnorr.PublicKey[E, S] {
	if spm == nil {
		return nil
	}
	return spm.publicKey
}

func (spm *PublicMaterial[E, S]) AccessStructure() *feldman.AccessStructure {
	if spm == nil {
		return nil
	}
	return spm.accessStructure
}

func (spm *PublicMaterial[E, S]) PartialPublicKeys() ds.Map[sharing.ID, *schnorr.PublicKey[E, S]] {
	if spm == nil {
		return nil
	}
	return spm.partialPublicKeys
}

func (spm *PublicMaterial[E, S]) VerificationVector() feldman.VerificationVector[E, S] {
	if spm == nil {
		return nil
	}
	return spm.fv
}

func (spm *PublicMaterial[E, S]) Equal(other *PublicMaterial[E, S]) bool {
	if spm == nil || other == nil {
		return spm == other
	}
	for id, pk := range spm.partialPublicKeys.Iter() {
		otherPk, exists := other.partialPublicKeys.Get(id)
		if !exists || !pk.Equal(otherPk) {
			return false
		}
	}
	return spm.publicKey.Equal(other.publicKey) &&
		spm.accessStructure.Equal(other.accessStructure) &&
		spm.fv.Equal(other.fv)
}

func (spm *PublicMaterial[E, S]) HashCode() base.HashCode {
	if spm == nil {
		return base.HashCode(0)
	}
	return spm.publicKey.HashCode()
}

type Shard[
	E algebra.PrimeGroupElement[E, S],
	S algebra.PrimeFieldElement[S],
] struct {
	share *feldman.Share[S]
	PublicMaterial[E, S]
}

func (sh *Shard[E, S]) Share() *feldman.Share[S] {
	if sh == nil {
		return nil
	}
	return sh.share
}

func (sh *Shard[E, S]) Equal(other *Shard[E, S]) bool {
	if sh == nil || other == nil {
		return sh == other
	}
	return sh.share.Equal(other.share) &&
		sh.PublicMaterial.Equal(&other.PublicMaterial)
}

func (sh *Shard[E, S]) PublicKeyMaterial() *PublicMaterial[E, S] {
	if sh == nil {
		return nil
	}
	return &sh.PublicMaterial
}

func (sh *Shard[E, S]) HashCode() base.HashCode {
	if sh == nil {
		return base.HashCode(0)
	}
	return sh.PublicMaterial.HashCode()
}

func (s *Shard[E, S]) AsSchnorrPrivateKey() (*schnorr.PrivateKey[E, S], error) {
	if s == nil || s.share == nil {
		return nil, errs.NewIsNil("shard or share is nil")
	}
	sk, err := schnorr.NewPrivateKey(s.share.Value(), s.publicKey)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create schnorr private key from share")
	}
	return sk, nil
}

func NewShard[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](
	share *feldman.Share[S],
	publicKey *schnorr.PublicKey[E, S],
	fv feldman.VerificationVector[E, S],
	accessStructure *feldman.AccessStructure,
) (*Shard[E, S], error) {
	if share == nil || publicKey == nil || accessStructure == nil {
		return nil, errs.NewIsNil("nil input parameters")
	}
	sf, ok := share.Value().Structure().(algebra.PrimeField[S])
	if !ok {
		return nil, errs.NewType("share value structure is not a prime field")
	}
	partialPublicKeyValues, err := gennaro.ComputePartialPublicKey(sf, share, fv, accessStructure)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to compute partial public keys from share")
	}
	partialPublicKeys := hashmap.NewComparable[sharing.ID, *schnorr.PublicKey[E, S]]()
	for id, value := range partialPublicKeyValues.Iter() {
		pk, err := schnorr.NewPublicKey(value)
		if err != nil {
			return nil, errs.WrapFailed(err, "failed to create public key for party %d", id)
		}
		partialPublicKeys.Put(id, pk)
	}

	return &Shard[E, S]{
		share: share,
		PublicMaterial: PublicMaterial[E, S]{
			publicKey:         publicKey,
			accessStructure:   accessStructure,
			fv:                fv,
			partialPublicKeys: partialPublicKeys.Freeze(),
		},
	}, nil
}
