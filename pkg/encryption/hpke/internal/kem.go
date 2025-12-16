package internal

import (
	"encoding/binary"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/curve25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	dh "github.com/bronlabs/bron-crypto/pkg/key_agreement/dh/dhc"
)

type KEMID uint16

// https://www.rfc-editor.org/rfc/rfc9180.html#name-key-encapsulation-mechanism
const (
	DHKEM_RESERVED           KEMID = 0x0000
	DHKEM_P256_HKDF_SHA256   KEMID = 0x0010
	DHKEM_X25519_HKDF_SHA256 KEMID = 0x0020
	P256BitMask                    = 0xff
)

// https://www.rfc-editor.org/rfc/rfc9180.html#name-key-encapsulation-mechanism
//
//nolint:exhaustive // reserved will not have have parameters below.
var (
	nSecrets = map[KEMID]int{
		DHKEM_P256_HKDF_SHA256:   32,
		DHKEM_X25519_HKDF_SHA256: 32,
	}
	nEncs = map[KEMID]int{
		DHKEM_P256_HKDF_SHA256:   65,
		DHKEM_X25519_HKDF_SHA256: 32,
	}
	nPKs = map[KEMID]int{
		DHKEM_P256_HKDF_SHA256:   65,
		DHKEM_X25519_HKDF_SHA256: 32,
	}
	nSKs = map[KEMID]int{
		DHKEM_P256_HKDF_SHA256:   32,
		DHKEM_X25519_HKDF_SHA256: 32,
	}
)

func NewDHKEM[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](curve curves.Curve[P, B, S], kdf *KDFScheme) (*DHKEMScheme[P, B, S], error) {
	if curve == nil {
		return nil, ErrInvalidArgument.WithMessage("curve is nil").WithStackFrame()
	}
	if curve.Name() != p256.NewCurve().Name() && curve.Name() != curve25519.NewPrimeSubGroup().Name() {
		return nil, ErrNotSupported.WithMessage("unsupported curve: %s", curve.Name()).WithStackFrame()
	}
	if kdf == nil {
		return nil, ErrInvalidArgument.WithMessage("kdf is nil").WithStackFrame()
	}
	return &DHKEMScheme[P, B, S]{
		curve: curve,
		kdf:   kdf,
	}, nil
}

type DHKEMScheme[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	curve curves.Curve[P, B, S]
	kdf   *KDFScheme
}

// ID returns KEM ID as per https://www.rfc-editor.org/rfc/rfc9180.html#name-key-encapsulation-mechanism
func (s *DHKEMScheme[P, B, S]) ID() KEMID {
	switch s.curve.Name() { //nolint:exhaustive // intentional, for readability.
	case p256.NewCurve().Name():
		return DHKEM_P256_HKDF_SHA256
	case curve25519.NewPrimeSubGroup().Name():
		return DHKEM_X25519_HKDF_SHA256
	default:
		panic("unsupported curve")
	}
}

func NewP256HKDFSha256KEM() *DHKEMScheme[*p256.Point, *p256.BaseFieldElement, *p256.Scalar] {
	return &DHKEMScheme[*p256.Point, *p256.BaseFieldElement, *p256.Scalar]{
		curve: p256.NewCurve(),
		kdf:   NewKDFSHA256(),
	}
}

func NewX25519HKDFSha256KEM() *DHKEMScheme[*curve25519.PrimeSubGroupPoint, *curve25519.BaseFieldElement, *curve25519.Scalar] {
	return &DHKEMScheme[*curve25519.PrimeSubGroupPoint, *curve25519.BaseFieldElement, *curve25519.Scalar]{
		curve: curve25519.NewPrimeSubGroup(),
		kdf:   NewKDFSHA256(),
	}
}

// GenerateKeyPair is a randomised algorithm to generate a key pair.
// https://www.rfc-editor.org/rfc/rfc9180.html#section-4-2.1.2.1
func (s *DHKEMScheme[P, B, S]) GenerateKeyPair(prng io.Reader) (*PrivateKey[S], *PublicKey[P, B, S], error) {
	if prng == nil {
		return nil, nil, ErrInvalidArgument.WithMessage("prng is nil").WithStackFrame()
	}

	ikm, err := s.produceIKM(prng)
	if err != nil {
		return nil, nil, errs2.Wrap(err)
	}

	privateKey, publicKey, err := s.DeriveKeyPair(ikm)
	if err != nil {
		return nil, nil, errs2.Wrap(err)
	}

	return privateKey, publicKey, nil
}

// DeriveKeyPair is a deterministic algorithm to derive a key pair (skX, pkX) from the byte string ikm, where ikm SHOULD have at least Nsk bytes of entropy.
// https://www.rfc-editor.org/rfc/rfc9180.html#name-derivekeypair
func (s *DHKEMScheme[P, B, S]) DeriveKeyPair(ikm []byte) (*PrivateKey[S], *PublicKey[P, B, S], error) {
	if len(ikm) < s.NSk() {
		return nil, nil, ErrInvalidLength.WithMessage("ikm length(=%d) < Nsk(=%d)", len(ikm), s.NSk()).WithStackFrame()
	}
	var skBytes []byte
	var skv S
	var err error

	switch s.curve.Name() {
	case p256.NewCurve().Name():
		dpkPrk := s.kdf.labeledExtract(s.suiteID(), nil, []byte("dkp_prk"), ikm)
		counter := uint8(0)
		skv = s.curve.ScalarField().Zero()
		for skv.IsZero() || err != nil {
			skBytes = s.kdf.labeledExpand(s.suiteID(), dpkPrk, []byte("candidate"), []byte{counter}, s.NSk())
			skBytes[0] &= P256BitMask

			skv, err = s.curve.ScalarField().FromBytes(skBytes)
			counter++
		}
	case curve25519.NewPrimeSubGroup().Name():
		dkpPrk := s.kdf.labeledExtract(s.suiteID(), nil, []byte("dkp_prk"), ikm)
		skBytes = s.kdf.labeledExpand(s.suiteID(), dkpPrk, []byte("sk"), nil, s.NSk())
		skv, err = algebra.StructureMustBeAs[interface {
			algebra.PrimeField[S]
			FromClampedBytes([]byte) (S, error)
		}](s.curve.ScalarStructure()).FromClampedBytes(skBytes)
		if err != nil {
			return nil, nil, errs2.Wrap(err)
		}
	default:
		return nil, nil, ErrNotSupported.WithMessage("curve %s not supported", s.curve.Name()).WithStackFrame()
	}
	sk, err := NewPrivateKey(s.curve.ScalarField(), skBytes)
	if err != nil {
		return nil, nil, errs2.Wrap(err)
	}
	pk, err := NewPublicKey(s.curve.ScalarBaseMul(skv))
	if err != nil {
		return nil, nil, errs2.Wrap(err)
	}
	return sk, pk, nil
}

// Encap is a randomised algorithm to generate an ephemeral, fixed-length symmetric key (the KEM shared secret) and a fixed-length encapsulation of that key that can be decapsulated by the holder of the private key corresponding to pkR. This function can raise an EncapError on encapsulation failure.
// https://www.rfc-editor.org/rfc/rfc9180.html#section-4-2.1.2.5
func (s *DHKEMScheme[P, B, S]) Encap(receiverPublicKey *PublicKey[P, B, S], prng io.Reader) (sharedSecret []byte, ephemeralPublicKey *PublicKey[P, B, S], err error) {
	if prng == nil {
		return nil, nil, ErrInvalidArgument.WithMessage("prng is nil").WithStackFrame()
	}

	ikmE, err := s.produceIKM(prng)
	if err != nil {
		return nil, nil, errs2.Wrap(err)
	}
	sharedSecret, ephemeralPublicKey, err = s.EncapWithIKM(receiverPublicKey, ikmE)
	if err != nil {
		return nil, nil, errs2.Wrap(err)
	}
	return sharedSecret, ephemeralPublicKey, nil
}

func (s *DHKEMScheme[P, B, S]) EncapWithIKM(receiverPublicKey *PublicKey[P, B, S], ikmE []byte) (sharedSecret []byte, ephemeralPublicKey *PublicKey[P, B, S], err error) {
	if receiverPublicKey == nil || ikmE == nil {
		return nil, nil, errs2.Wrap(err)
	}
	if receiverPublicKey.Value().IsOpIdentity() {
		return nil, nil, ErrInvalidPublicKey.WithMessage("receiver public key is identity").WithStackFrame()
	}
	if !receiverPublicKey.Value().IsTorsionFree() {
		return nil, nil, ErrInvalidPublicKey.WithMessage("Public Key not in the prime subgroup").WithStackFrame()
	}

	ephemeralPrivateKey, ephemeralPublicKey, err := s.DeriveKeyPair(ikmE)
	if err != nil {
		return nil, nil, errs2.Wrap(err)
	}

	dhReceiverPublicKey, err := dh.NewPublicKey(receiverPublicKey.Value())
	if err != nil {
		return nil, nil, errs2.Wrap(err)
	}
	dhKey, err := dh.DeriveSharedSecret(&ephemeralPrivateKey.ExtendedPrivateKey, dhReceiverPublicKey)
	if err != nil {
		return nil, nil, errs2.Wrap(err)
	}

	enc := ephemeralPublicKey.Bytes()
	pkRm := receiverPublicKey.Bytes()

	kemContext := make([]byte, len(enc)+len(pkRm))
	copy(kemContext, enc)
	copy(kemContext[len(enc):], pkRm)
	sharedSecret = s.extractAndExpand(dhKey.Bytes(), kemContext)
	return sharedSecret, ephemeralPublicKey, nil
}

// Decap is a deterministic algorithm using the private key skR to recover the ephemeral symmetric key (the KEM shared secret) from its encapsulated representation enc. This function can raise a DecapError on decapsulation failure.
// https://www.rfc-editor.org/rfc/rfc9180.html#section-4-2.1.2.6
func (s *DHKEMScheme[P, B, S]) Decap(receiverPrivateKey *PrivateKey[S], ephemeralPublicKey *PublicKey[P, B, S]) (sharedSecret []byte, err error) {
	if receiverPrivateKey == nil || ephemeralPublicKey == nil {
		return nil, errs2.Wrap(err)
	}
	if ephemeralPublicKey.Value().IsOpIdentity() {
		return nil, ErrInvalidPublicKey.WithMessage("ephemeral public key is identity").WithStackFrame()
	}
	if !ephemeralPublicKey.Value().IsTorsionFree() {
		return nil, ErrInvalidPublicKey.WithMessage("Public Key not in the prime subgroup").WithStackFrame()
	}

	curve := algebra.StructureMustBeAs[curves.Curve[P, B, S]](ephemeralPublicKey.Value().Structure())

	enc := ephemeralPublicKey.Bytes()

	dhEphemeralPublicKey, err := dh.NewPublicKey(ephemeralPublicKey.Value())
	if err != nil {
		return nil, errs2.Wrap(err)
	}
	dhKey, err := dh.DeriveSharedSecret(&receiverPrivateKey.ExtendedPrivateKey, dhEphemeralPublicKey)
	if err != nil {
		return nil, errs2.Wrap(err)
	}

	receiverPublicKey, err := NewPublicKey(curve.ScalarBaseMul(receiverPrivateKey.Value()))
	if err != nil {
		return nil, errs2.Wrap(err)
	}
	pkRm := receiverPublicKey.Bytes()
	kemContext := make([]byte, len(enc)+len(pkRm))
	copy(kemContext, enc)
	copy(kemContext[len(enc):], pkRm)

	sharedSecret = s.extractAndExpand(dhKey.Bytes(), kemContext)
	return sharedSecret, nil
}

// AuthEncap is the same as Encap(), and the outputs encode an assurance that the KEM shared secret was generated by the holder of the private key skS.
// https://www.rfc-editor.org/rfc/rfc9180.html#section-4-2.1.2.7
func (s *DHKEMScheme[P, B, S]) AuthEncap(receiverPublicKey *PublicKey[P, B, S], senderPrivateKey *PrivateKey[S], prng io.Reader) (sharedSecret []byte, ephemeralPublicKey *PublicKey[P, B, S], err error) {
	if prng == nil {
		return nil, nil, ErrInvalidArgument.WithMessage("prng is nil").WithStackFrame()
	}

	ikmE, err := s.produceIKM(prng)
	if err != nil {
		return nil, nil, errs2.Wrap(err)
	}

	sharedSecret, ephemeralPublicKey, err = s.AuthEncapWithIKM(receiverPublicKey, senderPrivateKey, ikmE)
	if err != nil {
		return nil, nil, errs2.Wrap(err)
	}

	return sharedSecret, ephemeralPublicKey, nil
}

func (s *DHKEMScheme[P, B, S]) AuthEncapWithIKM(receiverPublicKey *PublicKey[P, B, S], senderPrivateKey *PrivateKey[S], ikmE []byte) (sharedSecret []byte, ephemeralPublicKey *PublicKey[P, B, S], err error) {
	if receiverPublicKey == nil || senderPrivateKey == nil || ikmE == nil {
		return nil, nil, ErrInvalidArgument.WithMessage("arguments can't be nil").WithStackFrame()
	}
	if receiverPublicKey.Value().IsOpIdentity() {
		return nil, nil, ErrInvalidPublicKey.WithMessage("receiver public key is identity").WithStackFrame()
	}
	if !receiverPublicKey.Value().IsTorsionFree() {
		return nil, nil, ErrInvalidPublicKey.WithMessage("Public Key not in the prime subgroup").WithStackFrame()
	}

	curve := algebra.StructureMustBeAs[curves.Curve[P, B, S]](receiverPublicKey.Value().Structure())

	ephemeralPrivateKey, ephemeralPublicKey, err := s.DeriveKeyPair(ikmE)
	if err != nil {
		return nil, nil, errs2.Wrap(err)
	}

	dhReceiverPublicKey, err := dh.NewPublicKey(receiverPublicKey.Value())
	if err != nil {
		return nil, nil, errs2.Wrap(err)
	}

	dhER, err := dh.DeriveSharedSecret(&ephemeralPrivateKey.ExtendedPrivateKey, dhReceiverPublicKey)
	if err != nil {
		return nil, nil, errs2.Wrap(err)
	}

	dhSR, err := dh.DeriveSharedSecret(&senderPrivateKey.ExtendedPrivateKey, dhReceiverPublicKey)
	if err != nil {
		return nil, nil, errs2.Wrap(err)
	}

	dhERBytes := dhER.Bytes()
	dhSRBytes := dhSR.Bytes()
	dhBytes := make([]byte, len(dhERBytes)+len(dhSRBytes))
	copy(dhBytes, dhERBytes)
	copy(dhBytes[len(dhERBytes):], dhSRBytes)

	enc := ephemeralPublicKey.Bytes()
	pkRm := receiverPublicKey.Bytes()
	senderPublicKey, err := NewPublicKey(curve.ScalarBaseMul(senderPrivateKey.Value()))
	if err != nil {
		return nil, nil, errs2.Wrap(err)
	}
	pkSm := senderPublicKey.Bytes()
	kemContext := make([]byte, len(enc)+len(pkRm)+len(pkSm))
	copy(kemContext, enc)
	copy(kemContext[len(enc):], pkRm)
	copy(kemContext[len(enc)+len(pkRm):], pkSm)

	sharedSecret = s.extractAndExpand(dhBytes, kemContext)
	return sharedSecret, ephemeralPublicKey, nil
}

// AuthDecap is the same as Decap(), and the recipient is assured that the KEM shared secret was generated by the holder of the private key skS.
// https://www.rfc-editor.org/rfc/rfc9180.html#section-4-2.1.2.8
func (s *DHKEMScheme[P, B, S]) AuthDecap(receiverPrivateKey *PrivateKey[S], senderPublicKey, ephemeralPublicKey *PublicKey[P, B, S]) (sharedSecret []byte, err error) {
	if receiverPrivateKey == nil || senderPublicKey == nil || ephemeralPublicKey == nil {
		return nil, ErrInvalidArgument.WithMessage("arguments can't be nil").WithStackFrame()
	}
	if !senderPublicKey.Value().IsTorsionFree() {
		return nil, ErrInvalidPublicKey.WithMessage("Public Key not in the prime subgroup").WithStackFrame()
	}
	if !ephemeralPublicKey.Value().IsTorsionFree() {
		return nil, ErrInvalidPublicKey.WithMessage("Public Key not in the prime subgroup").WithStackFrame()
	}

	curve := algebra.StructureMustBeAs[curves.Curve[P, B, S]](ephemeralPublicKey.Value().Structure())

	dhEphemeralPublicKey, err := dh.NewPublicKey(ephemeralPublicKey.Value())
	if err != nil {
		return nil, errs2.Wrap(err)
	}
	dhSenderPublicKey, err := dh.NewPublicKey(senderPublicKey.Value())
	if err != nil {
		return nil, errs2.Wrap(err)
	}

	dhRE, err := dh.DeriveSharedSecret(&receiverPrivateKey.ExtendedPrivateKey, dhEphemeralPublicKey)
	if err != nil {
		return nil, errs2.Wrap(err)
	}

	dhRS, err := dh.DeriveSharedSecret(&receiverPrivateKey.ExtendedPrivateKey, dhSenderPublicKey)
	if err != nil {
		return nil, errs2.Wrap(err)
	}

	dhREBytes := dhRE.Bytes()
	dhRSBytes := dhRS.Bytes()
	dhBytes := make([]byte, len(dhREBytes)+len(dhRSBytes))
	copy(dhBytes, dhREBytes)
	copy(dhBytes[len(dhREBytes):], dhRSBytes)

	enc := ephemeralPublicKey.Bytes()
	receiverPK, err := NewPublicKey(curve.ScalarBaseMul(receiverPrivateKey.Value()))
	if err != nil {
		return nil, errs2.Wrap(err)
	}
	pkRm := receiverPK.Bytes()
	pkSm := senderPublicKey.Bytes()
	kemContext := make([]byte, len(enc)+len(pkRm)+len(pkSm))
	copy(kemContext, enc)
	copy(kemContext[len(enc):], pkRm)
	copy(kemContext[len(enc)+len(pkRm):], pkSm)

	sharedSecret = s.extractAndExpand(dhBytes, kemContext)
	return sharedSecret, nil
}

// NSecret is the length in bytes of a KEM shared secret produced by this KEM.
// https://www.rfc-editor.org/rfc/rfc9180.html#section-4-2.1.2.9
func (s *DHKEMScheme[P, B, S]) NSecret() int {
	return nSecrets[s.ID()]
}

// NEnc is the length in bytes of an encapsulated key produced by this KEM.
// https://www.rfc-editor.org/rfc/rfc9180.html#section-4-2.1.2.10
func (s *DHKEMScheme[P, B, S]) NEnc() int {
	return nEncs[s.ID()]
}

// NPk is the length in bytes of an encoded public key for this KEM.
// https://www.rfc-editor.org/rfc/rfc9180.html#section-4-2.1.2.11
func (s *DHKEMScheme[P, B, S]) NPk() int {
	return nPKs[s.ID()]
}

// NSk is the length in bytes of an encoded private key for this KEM.
// https://www.rfc-editor.org/rfc/rfc9180.html#section-4-2.1.2.12
func (s *DHKEMScheme[P, B, S]) NSk() int {
	return nSKs[s.ID()]
}

// extractAndExpand is an internal method used in other methods of DHKEM.
// https://www.rfc-editor.org/rfc/rfc9180.html#section-4.1-4
func (s *DHKEMScheme[P, B, S]) extractAndExpand(dhBytes, kmContext []byte) []byte {
	eaePrk := s.kdf.labeledExtract(s.suiteID(), nil, []byte("eae_prk"), dhBytes)
	sharedSecret := s.kdf.labeledExpand(s.suiteID(), eaePrk, []byte("shared_secret"), kmContext, s.kdf.Nh())
	return sharedSecret
}

func (s *DHKEMScheme[P, B, S]) suiteID() []byte {
	idBuffer := make([]byte, 2)
	binary.BigEndian.PutUint16(idBuffer, uint16(s.ID()))
	return append([]byte("KEM"), idBuffer...)
}

func (s *DHKEMScheme[P, B, S]) produceIKM(prng io.Reader) ([]byte, error) {
	ikm := make([]byte, s.NSk())
	if _, err := io.ReadFull(prng, ikm); err != nil {
		return nil, errs2.Wrap(err)
	}
	return ikm, nil
}
