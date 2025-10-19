package schnorrlike

import (
	"hash"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
	"github.com/bronlabs/bron-crypto/pkg/signatures"
)

const Name signatures.Name = "SchnorrLike"

type (
	VariantType string

	Group[GE GroupElement[GE, S], S Scalar[S]] algebra.PrimeGroup[GE, S]

	GroupElement[GE algebra.PrimeGroupElement[GE, S], S Scalar[S]] algebra.PrimeGroupElement[GE, S]

	ScalarField[S Scalar[S]]               algebra.PrimeField[S]
	Scalar[S algebra.PrimeFieldElement[S]] algebra.PrimeFieldElement[S]

	KeyGenerator[GE GroupElement[GE, S], S Scalar[S]] = signatures.KeyGenerator[*PrivateKey[GE, S], *PublicKey[GE, S]]

	Signer[VR Variant[GE, S, M], GE GroupElement[GE, S], S Scalar[S], M Message] interface {
		signatures.Signer[M, *Signature[GE, S]]
		Variant() VR
	}

	Verifier[VR Variant[GE, S, M], GE GroupElement[GE, S], S Scalar[S], M Message] interface {
		signatures.Verifier[*PublicKey[GE, S], M, *Signature[GE, S]]
		Variant() VR
	}

	Scheme[
		VR Variant[GE, S, M], GE GroupElement[GE, S], S Scalar[S], M Message,
		KG KeyGenerator[GE, S], SG Signer[VR, GE, S, M], VF Verifier[VR, GE, S, M],
	] interface {
		signatures.Scheme[*PrivateKey[GE, S], *PublicKey[GE, S], M, *Signature[GE, S], KG, SG, VF]
		Variant() VR
	}
)

type Variant[GE GroupElement[GE, S], S Scalar[S], M Message] interface {
	Type() VariantType
	HashFunc() func() hash.Hash
	ComputeNonceCommitment() (GE, S, error)
	ComputeChallenge(nonceCommitment GE, publicKeyValue GE, message M) (S, error)
	ComputeResponse(privateKeyValue, nonce, challenge S) (S, error)
	SerializeSignature(signature *Signature[GE, S]) ([]byte, error)
}

type Message signatures.Message

func NewPublicKey[PKV GroupElement[PKV, S], S Scalar[S]](value PKV) (*PublicKey[PKV, S], error) {
	if utils.IsNil(value) {
		return nil, errs.NewIsNil("value")
	}
	if value.IsOpIdentity() {
		return nil, errs.NewFailed("value is identity")
	}
	if !value.IsTorsionFree() {
		return nil, errs.NewFailed("value is not torsion free")
	}
	return &PublicKey[PKV, S]{
		PublicKeyTrait: signatures.PublicKeyTrait[PKV, S]{
			V: value,
		},
	}, nil
}

type PublicKey[PKV GroupElement[PKV, S], S Scalar[S]] struct {
	signatures.PublicKeyTrait[PKV, S]
}

type publicKeyDTO[PKV GroupElement[PKV, S], S Scalar[S]] struct {
	PK PKV `cbor:"publicKey"`
}

func (pk *PublicKey[PKV, S]) Equal(other *PublicKey[PKV, S]) bool {
	if pk == nil || other == nil {
		return pk == other
	}
	return pk.PublicKeyTrait.Equal(&other.PublicKeyTrait)
}

func (pk *PublicKey[PKV, S]) Clone() *PublicKey[PKV, S] {
	if pk == nil {
		return nil
	}
	return &PublicKey[PKV, S]{PublicKeyTrait: *pk.PublicKeyTrait.Clone()}
}

func (pk *PublicKey[PKV, S]) MarshalCBOR() ([]byte, error) {
	dto := &publicKeyDTO[PKV, S]{
		PK: pk.V,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "failed to marshal schnorrlike PublicKey")
	}
	return data, nil
}

func (pk *PublicKey[PKV, S]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*publicKeyDTO[PKV, S]](data)
	if err != nil {
		return err
	}
	pk2, err := NewPublicKey(dto.PK)
	if err != nil {
		return err
	}
	*pk = *pk2
	return nil
}

func NewPrivateKey[PKV GroupElement[PKV, SKV], SKV Scalar[SKV]](value SKV, publicKey *PublicKey[PKV, SKV]) (*PrivateKey[PKV, SKV], error) {
	if utils.IsNil(value) {
		return nil, errs.NewIsNil("value")
	}
	if value.IsOpIdentity() {
		return nil, errs.NewFailed("value is identity")
	}
	if publicKey == nil {
		return nil, errs.NewIsNil("publicKey")
	}
	return &PrivateKey[PKV, SKV]{
		PrivateKeyTrait: signatures.PrivateKeyTrait[PKV, SKV]{
			V:              value,
			PublicKeyTrait: publicKey.PublicKeyTrait,
		},
	}, nil
}

type PrivateKey[PKV GroupElement[PKV, SKV], SKV Scalar[SKV]] struct {
	signatures.PrivateKeyTrait[PKV, SKV]
}

func (sk *PrivateKey[PKV, SKV]) PublicKey() *PublicKey[PKV, SKV] {
	return &PublicKey[PKV, SKV]{PublicKeyTrait: sk.PublicKeyTrait}
}

func (sk *PrivateKey[PKV, SKV]) Name() signatures.Name {
	return Name
}

func (sk *PrivateKey[PKV, SKV]) Equal(other *PrivateKey[PKV, SKV]) bool {
	if sk == nil || other == nil {
		return sk == other
	}
	return sk.Name() == other.Name() && sk.PrivateKeyTrait.Equal(&other.PrivateKeyTrait)
}

func (sk *PrivateKey[PKV, SKV]) Clone() *PrivateKey[PKV, SKV] {
	if sk == nil {
		return nil
	}
	return &PrivateKey[PKV, SKV]{
		PrivateKeyTrait: *sk.PrivateKeyTrait.Clone(),
	}
}

func NewSignature[GE GroupElement[GE, S], S Scalar[S]](e S, r GE, s S) (*Signature[GE, S], error) {
	if utils.IsNil(s) {
		return nil, errs.NewIsNil("s")
	}
	if utils.IsNil(r) && utils.IsNil(e) {
		return nil, errs.NewIsNil("r and e can't both be nil")
	}
	return &Signature[GE, S]{
		E: e,
		R: r,
		S: s,
	}, nil
}

type Signature[GE GroupElement[GE, S], S Scalar[S]] struct {
	E S
	R GE
	S S
}

func (sig *Signature[GE, S]) Equal(other *Signature[GE, S]) bool {
	if sig == nil || other == nil {
		return sig == other
	}
	return sig.E.Equal(other.E) && sig.R.Equal(other.R) && sig.S.Equal(other.S)
}

func (sig *Signature[GE, S]) Clone() *Signature[GE, S] {
	if sig == nil {
		return nil
	}
	return &Signature[GE, S]{
		E: sig.E.Clone(),
		R: sig.R.Clone(),
		S: sig.S.Clone(),
	}
}

func (sig *Signature[GE, S]) HashCode() base.HashCode {
	return sig.E.HashCode() ^ sig.R.HashCode() ^ sig.S.HashCode()
}

type KeyGeneratorTrait[GE GroupElement[GE, S], S Scalar[S]] struct {
	Grp Group[GE, S]
	SF  ScalarField[S]
}

func (kg *KeyGeneratorTrait[GE, S]) Generate(prng io.Reader) (*PrivateKey[GE, S], *PublicKey[GE, S], error) {
	if prng == nil {
		return nil, nil, errs.NewIsNil("prng")
	}
	sc, err := algebrautils.RandomNonIdentity(kg.SF, prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "scalar")
	}
	pkv := kg.Grp.ScalarBaseOp(sc)
	pk, err := NewPublicKey(pkv)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "public key")
	}
	sk, err := NewPrivateKey(sc, pk)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "private key")
	}
	return sk, pk, nil
}

type SignerTrait[VR Variant[GE, S, M], GE GroupElement[GE, S], S Scalar[S], M Message] struct {
	Sk       *PrivateKey[GE, S]
	V        VR
	Verifier signatures.Verifier[*PublicKey[GE, S], M, *Signature[GE, S]]
}

func (sg *SignerTrait[VR, GE, S, M]) Sign(message M) (*Signature[GE, S], error) {
	R, k, err := sg.V.ComputeNonceCommitment()
	if err != nil {
		return nil, errs.WrapFailed(err, "R")
	}
	e, err := sg.V.ComputeChallenge(R, sg.Sk.PublicKey().Value(), message)
	if err != nil {
		return nil, errs.WrapFailed(err, "e")
	}
	s, err := sg.V.ComputeResponse(sg.Sk.Value(), k, e)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not compute response")
	}
	sigma := &Signature[GE, S]{
		E: e,
		R: R,
		S: s,
	}

	if err := sg.Verifier.Verify(sigma, sg.Sk.PublicKey(), message); err != nil {
		return nil, errs.WrapFailed(err, "signature verification failed")
	}
	return sigma, nil
}

func (sg *SignerTrait[VR, GE, S, M]) Variant() VR {
	return sg.V
}

type VerifierTrait[VR Variant[GE, S, M], GE GroupElement[GE, S], S Scalar[S], M Message] struct {
	V                          VR
	ChallengePublicKey         *PublicKey[GE, S]
	ResponseOperatorIsNegative bool
}

func (v *VerifierTrait[VR, GE, S, M]) Variant() VR {
	return v.V
}

func (v *VerifierTrait[VR, GE, S, M]) Verify(sigma *Signature[GE, S], publicKey *PublicKey[GE, S], message M) error {
	if publicKey == nil {
		return errs.NewIsNil("publicKey")
	}
	if publicKey.Value().IsOpIdentity() {
		return errs.NewIsNil("publicKey is identity")
	}
	challengeR := sigma.R
	challengePublicKey := publicKey
	if v.ChallengePublicKey != nil {
		challengePublicKey = v.ChallengePublicKey
	}
	e, err := v.V.ComputeChallenge(challengeR, challengePublicKey.V, message)
	if err != nil {
		return errs.WrapFailed(err, "e")
	}
	if !sigma.E.Equal(e) {
		return errs.NewFailed("e")
	}
	generator := publicKey.Group().Generator()
	rhsOperand := publicKey.Value().ScalarOp(e)
	if v.ResponseOperatorIsNegative {
		rhsOperand = rhsOperand.OpInv()
	}
	right := sigma.R.Op(rhsOperand)
	left := generator.ScalarOp(sigma.S)
	if !left.Equal(right) {
		return errs.NewVerification("signature verification failed")
	}
	return nil
}

func (v *VerifierTrait[VR, GE, S, M]) BatchVerify(signatures []*Signature[GE, S], publicKeys []*PublicKey[GE, S], messages []M) error {
	if len(signatures) != len(publicKeys) || len(signatures) != len(messages) {
		return errs.NewFailed("mismatched lengths")
	}
	for i := range signatures {
		if err := v.Verify(signatures[i], publicKeys[i], messages[i]); err != nil {
			return errs.WrapFailed(err, "batch verification failed")
		}
	}
	return nil
}

func _[GE GroupElement[GE, S], S Scalar[S]]() {
	var (
		_ signatures.PublicKey[*PublicKey[GE, S]]   = (*PublicKey[GE, S])(nil)
		_ signatures.PrivateKey[*PrivateKey[GE, S]] = (*PrivateKey[GE, S])(nil)
		_ signatures.Signature[*Signature[GE, S]]   = (*Signature[GE, S])(nil)
	)
}
