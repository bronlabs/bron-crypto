package tschnorr

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/signatures"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike"
	"github.com/bronlabs/bron-crypto/pkg/threshold/dkg/gennaro"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
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
	publicKey         *schnorrlike.PublicKey[E, S]
	accessStructure   *feldman.AccessStructure
	fv                feldman.VerificationVector[E, S]
	partialPublicKeys ds.Map[sharing.ID, *schnorrlike.PublicKey[E, S]]
}

type publicMaterialDTO[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	PublicKey         *schnorrlike.PublicKey[E, S]                `cbor:"publicKey"`
	AccessStructure   *feldman.AccessStructure                    `cbor:"accessStructure"`
	FV                feldman.VerificationVector[E, S]            `cbor:"verificationVector"`
	PartialPublicKeys map[sharing.ID]*schnorrlike.PublicKey[E, S] `cbor:"partialPublicKeys"`
}

func (spm *PublicMaterial[E, S]) PublicKey() *schnorrlike.PublicKey[E, S] {
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

func (spm *PublicMaterial[E, S]) PartialPublicKeys() ds.Map[sharing.ID, *schnorrlike.PublicKey[E, S]] {
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

func (spm *PublicMaterial[E, S]) MarshalCBOR() ([]byte, error) {
	ppk := make(map[sharing.ID]*schnorrlike.PublicKey[E, S])
	for k, v := range spm.partialPublicKeys.Iter() {
		ppk[k] = v
	}

	dto := &publicMaterialDTO[E, S]{
		PublicKey:         spm.publicKey,
		AccessStructure:   spm.accessStructure,
		FV:                spm.fv,
		PartialPublicKeys: ppk,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "failed to marshal tSchnorr PublicMaterial")
	}
	return data, nil
}

func (spm *PublicMaterial[E, S]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*publicMaterialDTO[E, S]](data)
	if err != nil {
		return err
	}

	ppk := hashmap.NewImmutableComparableFromNativeLike(dto.PartialPublicKeys)
	spm2 := &PublicMaterial[E, S]{
		publicKey:         dto.PublicKey,
		accessStructure:   dto.AccessStructure,
		fv:                dto.FV,
		partialPublicKeys: ppk,
	}
	*spm = *spm2
	return nil
}

type Shard[
	E algebra.PrimeGroupElement[E, S],
	S algebra.PrimeFieldElement[S],
] struct {
	share *feldman.Share[S]
	PublicMaterial[E, S]
}

type shardDTO[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	Share *feldman.Share[S]    `cbor:"share"`
	PM    PublicMaterial[E, S] `cbor:"publicMaterial"`
}

func (sh *Shard[E, S]) Share() *feldman.Share[S] {
	if sh == nil {
		return nil
	}
	return sh.share
}

func (sh *Shard[E, S]) Equal(other tsig.Shard[*schnorrlike.PublicKey[E, S], *feldman.Share[S], *feldman.AccessStructure]) bool {
	if sh == nil || other == nil {
		return sh == other
	}
	o, ok := other.(*Shard[E, S])
	return ok && sh.share.Equal(o.share) &&
		sh.PublicMaterial.Equal(&o.PublicMaterial)
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

func (sh *Shard[E, S]) AsSchnorrPrivateKey() (*schnorrlike.PrivateKey[E, S], error) {
	if sh == nil || sh.share == nil {
		return nil, errs.NewIsNil("shard or share is nil")
	}
	sk, err := schnorrlike.NewPrivateKey(sh.share.Value(), sh.publicKey)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create schnorr private key from share")
	}
	return sk, nil
}

func (sh *Shard[E, S]) MarshalCBOR() ([]byte, error) {
	dto := &shardDTO[E, S]{
		Share: sh.share,
		PM:    sh.PublicMaterial,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "failed to marshal tSchnorr Shard")
	}
	return data, nil
}

func (sh *Shard[E, S]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*shardDTO[E, S]](data)
	if err != nil {
		return err
	}

	sh2, err := NewShard(dto.Share, dto.PM.PublicKey(), dto.PM.VerificationVector(), dto.PM.AccessStructure())
	if err != nil {
		return err
	}
	*sh = *sh2
	return nil
}

func NewShard[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](
	share *feldman.Share[S],
	publicKey *schnorrlike.PublicKey[E, S],
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
	partialPublicKeys := hashmap.NewComparable[sharing.ID, *schnorrlike.PublicKey[E, S]]()
	for id, value := range partialPublicKeyValues.Iter() {
		pk, err := schnorrlike.NewPublicKey(value)
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
