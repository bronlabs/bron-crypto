package mina

import (
	"io"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/hashing/poseidon"
	"github.com/bronlabs/bron-crypto/pkg/signatures"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tschnorr"
)

type (
	Group        = pasta.PallasCurve
	GroupElement = pasta.PallasPoint
	ScalarField  = pasta.PallasScalarField
	Scalar       = pasta.PallasScalar

	Message    = ROInput
	PublicKey  = schnorrlike.PublicKey[*GroupElement, *Scalar]
	PrivateKey = schnorrlike.PrivateKey[*GroupElement, *Scalar]
	Signature  = schnorrlike.Signature[*GroupElement, *Scalar]
)

var (
	hashFunc = poseidon.NewLegacyHash
	group    = pasta.NewPallasCurve()
	sf       = pasta.NewPallasScalarField()

	SignatureSize  = group.ElementSize() + sf.ElementSize()
	PublicKeySize  = group.ElementSize()
	PrivateKeySize = sf.ElementSize()

	_ schnorrlike.Scheme[*Variant, *GroupElement, *Scalar, *Message, *KeyGenerator, *Signer, *Verifier]         = (*Scheme)(nil)
	_ tschnorr.MPCFriendlyScheme[*Variant, *GroupElement, *Scalar, *Message, *KeyGenerator, *Signer, *Verifier] = (*Scheme)(nil)
)

func NewPublicKey(point *GroupElement) (*PublicKey, error) {
	pk, err := schnorrlike.NewPublicKey(point)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create Mina public key")
	}
	return pk, nil
}

func NewPrivateKey(scalar *Scalar) (*PrivateKey, error) {
	if scalar == nil {
		return nil, errs.NewIsNil("scalar is nil")
	}
	if scalar.IsZero() {
		return nil, errs.NewValidation("scalar is zero")
	}
	pkv := group.ScalarBaseMul(scalar)
	pk, err := schnorrlike.NewPublicKey(pkv)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create public key")
	}
	sk, err := schnorrlike.NewPrivateKey(scalar, pk)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create Mina private key")
	}
	return sk, nil
}

func NewScheme(nid NetworkId, privateKey *PrivateKey) (*Scheme, error) {
	vr, err := NewDeterministicVariant(nid, privateKey)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create variant")
	}
	return &Scheme{
		vr: vr,
	}, nil
}

func NewRandomisedScheme(nid NetworkId, prng io.Reader) (*Scheme, error) {
	vr, err := NewRandomisedVariant(nid, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create variant")
	}
	return &Scheme{
		vr: vr,
	}, nil
}

type Scheme struct {
	vr *Variant
}

func (*Scheme) Name() signatures.Name {
	return schnorrlike.Name
}

func (s *Scheme) Variant() *Variant {
	return s.vr
}

func (s *Scheme) Keygen(opts ...KeyGeneratorOption) (*KeyGenerator, error) {
	kg := &KeyGenerator{
		schnorrlike.KeyGeneratorTrait[*GroupElement, *Scalar]{
			Grp: group,
			SF:  sf,
		},
	}
	for _, opt := range opts {
		if err := opt(kg); err != nil {
			return nil, errs.WrapFailed(err, "failed to apply key generator option")
		}
	}
	return kg, nil
}

func (s *Scheme) Signer(privateKey *PrivateKey, opts ...SignerOption) (*Signer, error) {
	if privateKey == nil {
		return nil, errs.NewIsNil("private key is nil")
	}
	verifier, err := s.Verifier()
	if err != nil {
		return nil, errs.WrapFailed(err, "verifier creation failed")
	}
	signer := &Signer{
		schnorrlike.SignerTrait[*Variant, *GroupElement, *Scalar, *Message]{
			Sk:       privateKey,
			V:        s.vr,
			Verifier: verifier,
		},
	}
	for _, opt := range opts {
		if err := opt(signer); err != nil {
			return nil, errs.WrapFailed(err, "failed to apply signer option")
		}
	}
	return signer, nil
}

func (s *Scheme) Verifier(opts ...VerifierOption) (*Verifier, error) {
	verifier := &Verifier{
		VerifierTrait: schnorrlike.VerifierTrait[*Variant, *GroupElement, *Scalar, *Message]{
			V:                          s.vr,
			ResponseOperatorIsNegative: false,
		},
	}
	for _, opt := range opts {
		if err := opt(verifier); err != nil {
			return nil, errs.WrapFailed(err, "failed to apply verifier option")
		}
	}
	return verifier, nil
}

func (s *Scheme) PartialSignatureVerifier(publicKey *PublicKey, opts ...signatures.VerifierOption[*Verifier, *PublicKey, *Message, *Signature]) (schnorrlike.Verifier[*Variant, *GroupElement, *Scalar, *Message], error) {
	if publicKey == nil {
		return nil, errs.NewIsNil("public key is nil")
	}
	verifier, err := s.Verifier(opts...)
	if err != nil {
		return nil, errs.WrapFailed(err, "verifier creation failed")
	}
	verifier.ChallengePublicKey = publicKey
	return verifier, nil
}

type KeyGeneratorOption = signatures.KeyGeneratorOption[*KeyGenerator, *PrivateKey, *PublicKey]

type KeyGenerator struct {
	schnorrlike.KeyGeneratorTrait[*GroupElement, *Scalar]
}

type SignerOption = signatures.SignerOption[*Signer, *Message, *Signature]

type Signer struct {
	schnorrlike.SignerTrait[*Variant, *GroupElement, *Scalar, *Message]
}

type VerifierOption = signatures.VerifierOption[*Verifier, *PublicKey, *Message, *Signature]

func VerifyWithPRNG(prng io.Reader) VerifierOption {
	return func(v *Verifier) error {
		if prng == nil {
			return errs.NewArgument("prng is nil")
		}
		v.prng = prng
		return nil
	}
}

type Verifier struct {
	schnorrlike.VerifierTrait[*Variant, *GroupElement, *Scalar, *Message]

	prng io.Reader
}

func SerializeSignature(signature *Signature) ([]byte, error) {
	if signature == nil {
		return nil, errs.NewIsNil("signature is nil")
	}
	// Mina uses LITTLE-ENDIAN for field elements
	rx, err := signature.R.AffineX()
	if err != nil {
		return nil, errs.WrapSerialisation(err, "failed to serialise signature")
	}

	// Convert R.x from big-endian to little-endian
	rxBytesBE := rx.Bytes()
	rxBytesLE := make([]byte, len(rxBytesBE))
	for i := range rxBytesBE {
		rxBytesLE[i] = rxBytesBE[len(rxBytesBE)-1-i]
	}

	// Convert S from big-endian to little-endian
	sBytesBE := signature.S.Bytes()
	sBytesLE := make([]byte, len(sBytesBE))
	for i := range sBytesBE {
		sBytesLE[i] = sBytesBE[len(sBytesBE)-1-i]
	}

	out := slices.Concat(rxBytesLE, sBytesLE)
	if len(out) != SignatureSize {
		return nil, errs.NewLength("invalid signature size. got :%d, need :%d", len(out), SignatureSize)
	}
	return out, nil
}

func DeserializeSignature(input []byte) (*Signature, error) {
	if len(input) != SignatureSize {
		return nil, errs.NewLength("invalid signature size. got :%d, need :%d", len(input), SignatureSize)
	}

	rxBytesLE := input[:group.ElementSize()]
	sBytesLE := input[group.ElementSize():]

	// Mina uses LITTLE-ENDIAN for field elements
	// Convert R.x from little-endian to big-endian
	rxBytesBE := make([]byte, len(rxBytesLE))
	for i := range rxBytesLE {
		rxBytesBE[i] = rxBytesLE[len(rxBytesLE)-1-i]
	}

	// Parse R.x as a base field element
	rx, err := group.BaseField().FromBytes(rxBytesBE)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "failed to parse R.x")
	}

	// Reconstruct R from x-coordinate
	// Mina signatures always have R with even y-coordinate (parity=0)
	R, err := group.FromAffineX(rx, false)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to reconstruct R from x-coordinate")
	}

	// Convert S from little-endian to big-endian
	sBytesBE := make([]byte, len(sBytesLE))
	for i := range sBytesLE {
		sBytesBE[i] = sBytesLE[len(sBytesLE)-1-i]
	}

	s, err := sf.FromBytes(sBytesBE)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "failed to create scalar from bytes")
	}

	return &Signature{
		R: R,
		S: s,
		// E is not stored in Mina signatures, it will be recomputed during verification
	}, nil
}
