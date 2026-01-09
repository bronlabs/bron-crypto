package bip340

import (
	"io"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/signatures"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tschnorr"
)

type (
	Group        = k256.Curve
	GroupElement = k256.Point
	ScalarField  = k256.ScalarField
	Scalar       = k256.Scalar

	Message    = []byte
	PublicKey  = schnorrlike.PublicKey[*GroupElement, *Scalar]
	PrivateKey = schnorrlike.PrivateKey[*GroupElement, *Scalar]
	Signature  = schnorrlike.Signature[*GroupElement, *Scalar]
)

const (
	AuxSizeBytes int = 32
)

var (
	_ schnorrlike.Scheme[*Variant, *k256.Point, *k256.Scalar, Message, *KeyGenerator, *Signer, *Verifier] = (*Scheme)(nil)
	_ schnorrlike.Variant[*GroupElement, *Scalar, Message]                                                = (*Variant)(nil)
	_ schnorrlike.KeyGenerator[*GroupElement, *Scalar]                                                    = (*KeyGenerator)(nil)
	_ schnorrlike.Signer[*Variant, *GroupElement, *Scalar, Message]                                       = (*Signer)(nil)
	_ schnorrlike.Verifier[*Variant, *GroupElement, *Scalar, Message]

	_ tschnorr.MPCFriendlyScheme[*Variant, *GroupElement, *Scalar, Message, *KeyGenerator, *Signer, *Verifier] = (*Scheme)(nil)
	_ tschnorr.MPCFriendlyVariant[*GroupElement, *Scalar, Message]                                             = (*Variant)(nil)
)

func NewPublicKey(point *GroupElement) (*PublicKey, error) {
	pk, err := schnorrlike.NewPublicKey(point)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create BIP340 public key")
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
	pkv := k256.NewCurve().ScalarBaseMul(scalar)
	pk, err := schnorrlike.NewPublicKey(pkv)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create public key")
	}
	sk, err := schnorrlike.NewPrivateKey(scalar, pk)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create BIP340 private key")
	}
	return sk, nil
}

func NewSchemeWithAux(aux [AuxSizeBytes]byte) *Scheme {
	return &Scheme{
		aux: aux,
	}
}

func NewScheme(prng io.Reader) (*Scheme, error) {
	if prng == nil {
		return nil, errs.NewArgument("prng is nil")
	}

	aux := [AuxSizeBytes]byte{}
	_, err := io.ReadFull(prng, aux[:])
	if err != nil {
		return nil, errs.WrapRandomSample(err, "cannot generate nonce")
	}
	return &Scheme{
		aux: aux,
	}, nil
}

type Scheme struct {
	aux [AuxSizeBytes]byte
}

func (s Scheme) Name() signatures.Name {
	return schnorrlike.Name
}

func (s *Scheme) Variant() *Variant {
	return &Variant{
		Aux: s.aux,
	}
}

func (s *Scheme) Keygen(opts ...KeyGeneratorOption) (*KeyGenerator, error) {
	out := &KeyGenerator{
		KeyGeneratorTrait: schnorrlike.KeyGeneratorTrait[*GroupElement, *Scalar]{
			Grp: k256.NewCurve(),
			SF:  k256.NewScalarField(),
		},
	}
	for _, opt := range opts {
		if err := opt(out); err != nil {
			return nil, errs.WrapFailed(err, "key generator option failed")
		}
	}
	return out, nil
}

func (s *Scheme) Signer(privateKey *PrivateKey, opts ...SignerOption) (*Signer, error) {
	if privateKey == nil {
		return nil, errs.NewArgument("private key is nil")
	}
	variant := &Variant{
		Aux: s.aux,
		sk:  privateKey,
	}
	out := &Signer{
		sg: schnorrlike.SignerTrait[*Variant, *GroupElement, *Scalar, Message]{
			Sk: privateKey,
			V:  variant,
			Verifier: &Verifier{
				variant: variant,
			},
		},
	}
	for _, opt := range opts {
		if err := opt(out); err != nil {
			return nil, errs.WrapFailed(err, "signer option failed")
		}
	}
	return out, nil
}

func (s *Scheme) Verifier(opts ...VerifierOption) (*Verifier, error) {
	out := &Verifier{
		variant: s.Variant(),
	}
	for _, opt := range opts {
		if err := opt(out); err != nil {
			return nil, errs.WrapFailed(err, "verifier option failed")
		}
	}
	return out, nil
}

func (s *Scheme) PartialSignatureVerifier(
	publicKey *PublicKey,
	opts ...signatures.VerifierOption[*Verifier, *PublicKey, Message, *Signature],
) (schnorrlike.Verifier[*Variant, *GroupElement, *Scalar, Message], error) {
	if publicKey == nil || publicKey.Value() == nil {
		return nil, errs.NewArgument("public key is nil or invalid")
	}
	verifier, err := s.Verifier(opts...)
	if err != nil {
		return nil, errs.WrapFailed(err, "verifier creation failed")
	}
	verifier.challengePublicKey = publicKey
	return verifier, nil
}

func NewSignatureFromBytes(input []byte) (*Signature, error) {
	if len(input) != 64 {
		return nil, errs.NewSerialisation("invalid length")
	}

	r, err := decodePoint(input[:32])
	if err != nil {
		return nil, errs.NewSerialisation("invalid signature")
	}
	s, err := k256.NewScalarField().FromBytes(input[32:])
	if err != nil {
		return nil, errs.NewSerialisation("invalid signature")
	}
	return &Signature{
		R: r,
		S: s,
	}, nil
}

type KeyGeneratorOption = signatures.KeyGeneratorOption[*KeyGenerator, *PrivateKey, *PublicKey]

type KeyGenerator struct {
	schnorrlike.KeyGeneratorTrait[*GroupElement, *Scalar]
}

type SignerOption = signatures.SignerOption[*Signer, Message, *Signature]

type Signer struct {
	sg schnorrlike.SignerTrait[*Variant, *GroupElement, *Scalar, Message]
}

func (s *Signer) Sign(message Message) (*Signature, error) {
	// ComputeNonceCommitment requires a message
	s.sg.V.msg = message
	sig, err := s.sg.Sign(message)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to sign message")
	}
	return sig, nil
}

func (s *Signer) Variant() *Variant {
	return s.sg.V
}

type VerifierOption = signatures.VerifierOption[*Verifier, *PublicKey, Message, *Signature]

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
	variant            *Variant
	prng               io.Reader
	challengePublicKey *PublicKey
}

func (v *Verifier) Variant() *Variant {
	return v.variant
}

func (v *Verifier) Verify(signature *Signature, publicKey *PublicKey, message Message) error {
	if publicKey == nil || publicKey.Value() == nil {
		return errs.NewArgument("curve not supported")
	}
	if signature == nil || signature.R == nil || signature.S == nil || signature.R.IsZero() || signature.S.IsZero() {
		return errs.NewVerification("some signature elements are nil/zero")
	}
	if publicKey.Value().IsOpIdentity() {
		return errs.NewVerification("public key is identity")
	}
	if !publicKey.Value().IsTorsionFree() {
		return errs.NewValidation("Public Key not in the prime subgroup")
	}

	challengePublicKeyValue := LiftX(publicKey.Value())
	if v.challengePublicKey != nil {
		// TODO: should this be lifted?
		challengePublicKeyValue = v.challengePublicKey.Value()
	}

	// 1. Let P = lift_x(int(pk)).
	// 2. (implicit) Let r = int(sig[0:32]); fail if r ≥ p.
	// 3. (implicit) Let s = int(sig[32:64]); fail if s ≥ n.
	bigP := LiftX(publicKey.Value())

	// 4. Let e = int(hashBIP0340/challenge(bytes(r) || bytes(P) || m)) mod n.
	e, err := v.variant.ComputeChallenge(signature.R, challengePublicKeyValue, message)
	if err != nil {
		return errs.WrapFailed(err, "cannot create challenge scalar")
	}

	if signature.E != nil && !signature.E.Equal(e) {
		return errs.NewFailed("incompatible signature")
	}

	// 5. Let R = s⋅G - e⋅P.
	bigR := k256.NewCurve().ScalarBaseMul(signature.S).Sub(bigP.ScalarMul(e))

	// 6. Fail if is_infinite(R).
	if bigR.IsZero() {
		return errs.NewVerification("signature is invalid")
	}

	// 7. Fail if not has_even_y(R).
	ry, err := bigR.AffineY()
	if err != nil {
		return errs.WrapFailed(err, "cannot compute y coordinate")
	}
	if ry.IsOdd() {
		return errs.NewVerification("signature is invalid")
	}

	// 8. Fail if x(R) ≠ r.
	sigRx, err := signature.R.AffineX()
	if err != nil {
		return errs.WrapFailed(err, "cannot compute x coordinate")
	}
	rx, err := bigR.AffineX()
	if err != nil {
		return errs.WrapFailed(err, "cannot compute x coordinate")
	}
	if !sigRx.Equal(rx) {
		return errs.NewVerification("signature is invalid")
	}
	return nil
}

func (v *Verifier) BatchVerify(signatures []*Signature, publicKeys []*PublicKey, messages []Message, prng io.Reader) error {
	if v.prng == nil {
		return errs.NewIsNil("batch verification requires a prng. Initialise the verifier with the prng option")
	}
	if len(publicKeys) != len(signatures) || len(signatures) != len(messages) || len(signatures) == 0 {
		return errs.NewArgument("length of publickeys, messages and signatures must be equal and greater than zero")
	}
	if sliceutils.Any(publicKeys, func(pk *PublicKey) bool {
		return pk == nil || pk.Value() == nil || pk.Value().IsOpIdentity()
	}) {

		return errs.NewArgument("some public keys are nil or identity")
	}
	curve := k256.NewCurve()
	sf := k256.NewScalarField()
	var err error
	// 1. Generate u-1 random integers a2...u in the range 1...n-1.
	a := make([]*k256.Scalar, len(signatures))
	a[0] = sf.One()
	for i := 1; i < len(signatures); i++ {
		a[i], err = algebrautils.RandomNonIdentity(sf, prng)
		if err != nil {
			return errs.WrapRandomSample(err, "cannot generate random scalar for i=%d", i)
		}
	}

	// For i = 1 .. u:
	left := sf.Zero()
	ae := make([]*k256.Scalar, len(signatures))
	bigR := make([]*k256.Point, len(signatures))
	bigP := make([]*k256.Point, len(signatures))
	for i, sig := range signatures {
		// 2. Let P_i = lift_x(int(pki))
		// 3. (implicit) Let r_i = int(sigi[0:32]); fail if ri ≥ p.
		// 4. (implicit) Let s_i = int(sigi[32:64]); fail if si ≥ n.
		bigP[i] = LiftX(publicKeys[i].Value())

		// 5. Let ei = int(hashBIP0340/challenge(bytes(r_i) || bytes(P_i) || mi)) mod n.
		e, err := v.variant.ComputeChallenge(sig.R, publicKeys[i].V, messages[i])
		if err != nil {
			return errs.WrapFailed(err, "invalid signature")
		}

		// 6. Let Ri = lift_x(ri); fail if lift_x(ri) fails.
		bigR[i] = LiftX(signatures[i].R)

		ae[i] = a[i].Mul(e)
		left = left.Add(a[i].Mul(sig.S))
	}

	// 7. Fail if (s1 + a2s2 + ... + ausu)⋅G ≠ R1 + a2⋅R2 + ... + au⋅Ru + e1⋅P1 + (a2e2)⋅P2 + ... + (aueu)⋅Pu.
	rightA, err := curve.MultiScalarMul(a, bigR)
	if err != nil {
		return errs.WrapFailed(err, "failed to multiply scalars and points")
	}
	rightB, err := curve.MultiScalarMul(ae, bigP)
	if err != nil {
		return errs.WrapFailed(err, "failed to multiply scalars and points")
	}
	right := rightA.Add(rightB)
	if !curve.Generator().ScalarMul(left).Equal(right) {
		return errs.NewVerification("signature is invalid")
	}

	// Return success iff no failure occurred before reaching this point.
	return nil
}

func LiftX(p *k256.Point) *k256.Point {
	if p.IsZero() {
		return p
	}

	py, err := p.AffineY()
	if err != nil {
		panic("this should never happen")
	}
	if py.IsOdd() {
		return p.Neg()
	}
	return p
}

func SerializeSignature(signature *Signature) ([]byte, error) {
	if signature == nil || signature.R == nil || signature.S == nil {
		return nil, errs.NewArgument("signature is nil")
	}
	return slices.Concat(signature.R.ToCompressed()[1:], signature.S.Bytes()), nil
}

func NewPublicKeyFromBytes(input []byte) (*PublicKey, error) {
	p, err := decodePoint(input)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot decode point")
	}
	pk, err := NewPublicKey(p)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create public key")
	}
	return pk, nil
}

func SerializePublicKey(publicKey *PublicKey) ([]byte, error) {
	if publicKey == nil {
		return nil, errs.NewArgument("public key is nil")
	}
	return publicKey.Value().ToCompressed()[1:], nil
}

func encodePoint(p *k256.Point) []byte {
	return p.ToCompressed()[1:]
}

func decodePoint(data []byte) (*k256.Point, error) {
	curve := k256.NewCurve()
	p, err := curve.FromCompressed(slices.Concat([]byte{0x02}, data))
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot decode point")
	}

	return p, nil
}
