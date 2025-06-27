package bip340

import (
	"crypto/subtle"
	"hash"
	"io"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/bron-crypto/pkg/hashing/bip340"
	"github.com/bronlabs/bron-crypto/pkg/signatures"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/additive"
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
	VariantType  schnorrlike.VariantType = "bip340"
	AuxSizeBytes int                     = 32
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
	return schnorrlike.NewPublicKey(point)
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
	return schnorrlike.NewPrivateKey(scalar, pk)
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

func NewVariant(aux [AuxSizeBytes]byte, opts ...VariantOption) (*Variant, error) {
	out := &Variant{
		Aux: aux,
	}
	for i, opt := range opts {
		if err := opt(out); err != nil {
			return nil, errs.WrapFailed(err, "could not apply option %d", i)
		}
	}
	return out, nil
}

type Scheme struct {
	aux [AuxSizeBytes]byte
}

func (s Scheme) Name() signatures.Name {
	return schnorrlike.Name
}

func (s *Scheme) Variant(opts ...VariantOption) (*Variant, error) {
	return NewVariant(s.aux, opts...)
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
	verifier, err := s.Verifier()
	if err != nil {
		return nil, errs.WrapFailed(err, "verifier creation failed")
	}
	out := &Signer{
		sg: schnorrlike.RandomisedSignerTrait[*Variant, *GroupElement, *Scalar, Message]{
			Sk:       privateKey,
			Verifier: verifier,
		},
		aux: s.aux,
	}
	for _, opt := range opts {
		if err := opt(out); err != nil {
			return nil, errs.WrapFailed(err, "signer option failed")
		}
	}
	return out, nil
}

func (s *Scheme) Verifier(opts ...VerifierOption) (*Verifier, error) {
	variant, err := s.Variant()
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct variant")
	}
	out := &Verifier{
		variant: variant,
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

type VariantOption = schnorrlike.VariantOption[*Variant, *k256.Point, *k256.Scalar, Message]

func VariantWithPrivateKey(privateKey *PrivateKey) VariantOption {
	return func(variant *Variant) error {
		variant.sk = privateKey
		return nil
	}
}

func VariantWithMessage(message Message) VariantOption {
	return func(variant *Variant) error {
		variant.msg = message
		return nil
	}
}

type Variant struct {
	sk  *PrivateKey
	Aux [AuxSizeBytes]byte
	msg Message
}

func (*Variant) Type() schnorrlike.VariantType {
	return VariantType
}
func (*Variant) HashFunc() func() hash.Hash {
	return bip340.NewBip340HashChallenge
}

func (v *Variant) ComputeNonceCommitment() (*GroupElement, *Scalar, error) {
	if v.sk == nil || v.msg == nil {
		return nil, nil, errs.NewIsNil("need both private key and message")
	}
	g := k256.NewCurve().Generator()
	f := k256.NewScalarField()
	// 1. Let d' = int(sk)
	dPrime := v.sk.Value()
	// 2. Fail if d' = 0 or d' ≥ n
	if dPrime.IsZero() {
		return nil, nil, errs.NewFailed("d' is invalid")
	}
	// 3. Let P = d'⋅G
	bigP := g.ScalarMul(v.sk.Value())
	// 4. Let d = d' if P.y even, otherwise let d = n - d'
	d := dPrime
	if bigP.AffineY().IsOdd() {
		d = dPrime.Neg()
	}
	// 5. Let t be the byte-wise xor of bytes(d) and hashBIP0340/aux(a).
	auxDigest, err := hashing.Hash(bip340.NewBip340HashAux, v.Aux[:])
	if err != nil {
		return nil, nil, errs.WrapHashing(err, "hash failed")
	}
	t := make([]byte, len(auxDigest))
	if n := subtle.XORBytes(t, d.Bytes(), auxDigest); n != len(d.Bytes()) {
		return nil, nil, errs.NewFailed("invalid scalar bytes length")
	}
	// 6. Let rand = hashBIP0340/nonce(t || bytes(P) || m).
	rand, err := hashing.Hash(
		bip340.NewBip340HashNonce, t, encodePoint(bigP), v.msg,
	)
	if err != nil {
		return nil, nil, errs.WrapHashing(err, "hash failed")
	}

	// 7. Let k' = int(rand) mod n.
	kPrime, err := f.FromWideBytes(rand)
	if err != nil {
		return nil, nil, errs.NewFailed("cannot set k'")
	}

	// 8. Fail if k' = 0
	if kPrime.IsZero() {
		return nil, nil, errs.NewFailed("k' is invalid")
	}

	// 9. Let R = k'⋅G.
	bigR := g.ScalarMul(kPrime)
	// 10. Let k = k' if R.y is even, otherwise let k = n - k', R = k ⋅ G
	k := kPrime
	if bigR.AffineY().IsOdd() {
		k = kPrime.Neg()
		bigR = g.ScalarMul(k)
	}
	return bigR, k, nil
}

func (v *Variant) ComputeChallenge(nonceCommitment, publicKeyValue *GroupElement, message Message) (*Scalar, error) {
	// 11. Let e = int(hashBIP0340/challenge(bytes(R) || bytes(P) || m)) mod n.
	roinput := slices.Concat(
		nonceCommitment.ToCompressed()[1:],
		publicKeyValue.ToCompressed()[1:],
		message,
	)

	e, err := schnorrlike.MakeGenericChallenge(k256.NewScalarField(), v.HashFunc(), false, roinput)
	if err != nil {
		return nil, errs.WrapHashing(err, "hash failed")
	}
	return e, nil
}

func (*Variant) ComputeResponse(privateKeyValue, nonce, challenge *Scalar) (*Scalar, error) {
	if privateKeyValue == nil || nonce == nil || challenge == nil {
		return nil, errs.NewIsNil("arguments")
	}
	// 12. Let sig = (R, (k + ed) mod n)).
	return nonce.Add(challenge.Mul(privateKeyValue)), nil
}

func (*Variant) SerializeSignature(signature *Signature) ([]byte, error) {
	return SerializeSignature(signature)
}

func (*Variant) NonceIsFunctionOfMessage() bool {
	return true
}

func (v *Variant) Clone() *Variant {
	out := &Variant{
		Aux: v.Aux,
	}
	if v.sk != nil {
		out.sk = v.sk.Clone()
	}
	if v.msg != nil {
		copy(out.msg, v.msg)
	}
	return out
}

type KeyGeneratorOption = signatures.KeyGeneratorOption[*KeyGenerator, *PrivateKey, *PublicKey]

type KeyGenerator struct {
	schnorrlike.KeyGeneratorTrait[*GroupElement, *Scalar]
}

type SignerOption = signatures.SignerOption[*Signer, Message, *Signature]

type Signer struct {
	sg  schnorrlike.RandomisedSignerTrait[*Variant, *GroupElement, *Scalar, Message]
	aux [AuxSizeBytes]byte
}

func (s *Signer) Sign(message Message) (*Signature, error) {
	// ComputeNonceCommitment requires a message
	messageBoundedVariant, err := NewVariant(
		s.aux, VariantWithMessage(message), VariantWithPrivateKey(s.sg.Sk),
	)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not bound message to variant")
	}
	s.sg.V = messageBoundedVariant
	return s.sg.Sign(message)
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

	// 1. Let P = lift_x(int(pk)).
	// 2. (implicit) Let r = int(sig[0:32]); fail if r ≥ p.
	// 3. (implicit) Let s = int(sig[32:64]); fail if s ≥ n.
	bigP := publicKey.Value()
	if bigP.AffineY().IsOdd() {
		bigP = bigP.Neg()
	}

	// 4. Let e = int(hashBIP0340/challenge(bytes(r) || bytes(P) || m)) mod n.
	var err error
	var e *k256.Scalar
	if v.challengePublicKey == nil {
		e, err = v.variant.ComputeChallenge(signature.R, publicKey.V, message)
	} else {
		e, err = v.variant.ComputeChallenge(signature.R, v.challengePublicKey.Value(), message)
	}
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
	if bigR.AffineY().IsOdd() {
		return errs.NewVerification("signature is invalid")
	}

	// 8. Fail if x(R) ≠ r.
	if !signature.R.AffineX().Equal(bigR.AffineX()) {
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
		return pk == nil || pk.Value() == nil || pk.Value().IsOpIdentity() || pk.Value().IsOpIdentity()
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
		bigP[i] = publicKeys[i].Value()
		if bigP[i].AffineY().IsOdd() {
			bigP[i] = bigP[i].Neg()
		}

		// 5. Let ei = int(hashBIP0340/challenge(bytes(r_i) || bytes(P_i) || mi)) mod n.
		e, err := v.variant.ComputeChallenge(sig.R, publicKeys[i].V, messages[i])
		if err != nil {
			return errs.WrapFailed(err, "invalid signature")
		}

		// 6. Let Ri = lift_x(ri); fail if lift_x(ri) fails.
		bigR[i] = signatures[i].R

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

// ============ MPC Methods ============

var _ tschnorr.MPCFriendlyVariant[*k256.Point, *k256.Scalar, Message] = (*Variant)(nil)

func (v *Variant) CorrectAdditiveSecretShareParity(publicKey *PublicKey, share *additive.Share[*k256.Scalar]) (*additive.Share[*k256.Scalar], error) {
	if publicKey == nil || share == nil {
		return nil, errs.NewIsNil("public key or secret share is nil")
	}
	out := share.Clone()
	if publicKey.Value().AffineY().IsOdd() {
		// If the public key is odd, we need to negate the additive share
		// to ensure that the parity of the nonce commitment is correct.
		out, _ = additive.NewShare(share.ID(), share.Value().Neg(), nil)
	}
	return out, nil
}

func (v *Variant) CorrectPartialNonceParity(nonceCommitment *k256.Point, k *k256.Scalar) (*k256.Point, *k256.Scalar, error) {
	if nonceCommitment == nil || k == nil {
		return nil, nil, errs.NewIsNil("nonce commitment or k is nil")
	}
	correctedK := k.Clone()
	if nonceCommitment.AffineY().IsOdd() {
		// If the nonce commitment is odd, we need to negate k to ensure that the parity is correct.
		correctedK = correctedK.Neg()
	}
	correctedR := k256.NewCurve().ScalarBaseOp(correctedK)
	return correctedR, correctedK, nil
}
