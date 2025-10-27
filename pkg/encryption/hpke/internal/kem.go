package internal

import (
	"crypto"
	"encoding/binary"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/key_agreement/dh/dhc"
	// "github.com/bronlabs/bron-crypto/pkg/key_agreement/dh"
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
		DHKEM_P256_HKDF_SHA256: 32,
		// DHKEM_X25519_HKDF_SHA256: 32,
	}
	nEncs = map[KEMID]int{
		DHKEM_P256_HKDF_SHA256: 65,
		// DHKEM_X25519_HKDF_SHA256: 32,
	}
	nPKs = map[KEMID]int{
		DHKEM_P256_HKDF_SHA256: 65,
		// DHKEM_X25519_HKDF_SHA256: 32,
	}
	nSKs = map[KEMID]int{
		DHKEM_P256_HKDF_SHA256: 32,
		// DHKEM_X25519_HKDF_SHA256: 32,
	}
	// kems = map[KEMID]*DHKEMScheme[P, B, S]{
	// 	DHKEM_P256_HKDF_SHA256:   NewP256HKDFSha256Scheme(),
	// 	DHKEM_X25519_HKDF_SHA256: NewX25519HKDFSha256Scheme(),
	// }
)

func NewDHKEM[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](curve curves.Curve[P, B, S], kdf *KDFScheme) (*DHKEMScheme[P, B, S], error) {
	if curve == nil {
		return nil, errs.NewIsNil("curve is nil")
	}
	if curve.Name() != p256.NewCurve().Name() {
		return nil, errs.NewCurve("unsupported curve: %s", curve.Name())
	}
	if kdf == nil {
		return nil, errs.NewIsNil("kdf is nil")
	}
	if kdf.hash != crypto.SHA256 {
		return nil, errs.NewType("unsupported kdf hash: %v", kdf.hash)
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
		switch s.kdf.hash { //nolint:exhaustive // intentional, for readability.
		case crypto.SHA256:
			return DHKEM_P256_HKDF_SHA256
		default:
			panic("unsupported kdf hash")
		}
	default:
		panic("unsupported curve")
	}
}

// func NewP256HKDFSha256KEMScheme() *DHKEMScheme[*p256.Point, *p256.BaseFieldElement, *p256.Scalar] {
// 	return &DHKEMScheme[*p256.Point, *p256.BaseFieldElement, *p256.Scalar]{
// 		curve: p256.NewCurve(),
// 		kdf:   NewKDFSHA256(),
// 	}
// }

// GenerateKeyPair is a randomised algorithm to generate a key pair.
// https://www.rfc-editor.org/rfc/rfc9180.html#section-4-2.1.2.1
func (s *DHKEMScheme[P, B, S]) GenerateKeyPair(prng io.Reader) (*PrivateKey[S], *PublicKey[P, B, S], error) {
	if prng == nil {
		return nil, nil, errs.NewIsNil("prng is nil")
	}

	ikm, err := s.produceIKM(prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not produce ikm")
	}

	privateKey, publicKey, err := s.DeriveKeyPair(ikm)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not produce key pair")
	}

	return privateKey, publicKey, nil
}

// DeriveKeyPair is a deterministic algorithm to derive a key pair (skX, pkX) from the byte string ikm, where ikm SHOULD have at least Nsk bytes of entropy.
// https://www.rfc-editor.org/rfc/rfc9180.html#name-derivekeypair
func (s *DHKEMScheme[P, B, S]) DeriveKeyPair(ikm []byte) (*PrivateKey[S], *PublicKey[P, B, S], error) {
	if len(ikm) < s.NSk() {
		return nil, nil, errs.NewLength("ikm length(=%d) < Nsk(=%d)", len(ikm), s.NSk())
	}

	switch s.curve.Name() {
	case p256.NewCurve().Name():
		dpkPrk := s.kdf.labeledExtract(s.suiteID(), nil, []byte("dkp_prk"), ikm)
		counter := 0
		skv := s.curve.ScalarField().Zero()
		var err error
		for skv.IsZero() || err != nil {
			if counter > 255 {
				return nil, nil, errs.NewFailed("DeriveKeyPairError")
			}
			skBytes := s.kdf.labeledExpand(s.suiteID(), dpkPrk, []byte("candidate"), []byte{uint8(counter)}, s.NSk())
			skBytes[0] &= P256BitMask

			skv, err = s.curve.ScalarField().FromBytes(skBytes)
			counter++
		}
		return &PrivateKey[S]{
				v: skv,
			}, &PublicKey[P, B, S]{
				v: s.curve.ScalarBaseMul(skv),
			}, nil

	// case curve25519.Name:
	// 	dkpPrk := s.kdf.labeledExtract(s.suiteID(), nil, []byte("dkp_prk"), ikm)
	// 	skBytes := s.kdf.labeledExpand(s.suiteID(), dkpPrk, []byte("sk"), nil, s.NSk())
	// 	sk, err := s.curve.ScalarField().Element().SetBytes(skBytes)
	// 	if err != nil {
	// 		return nil, errs.WrapSerialisation(err, "cannot deserialize scalar for %s", s.curve.Name())
	// 	}

	// 	return &PrivateKey{
	// 		D:         sk,
	// 		PublicKey: s.curve.ScalarBaseMult(sk),
	// 	}, nil
	default:
		return nil, nil, errs.NewCurve("curve %s not supported", s.curve.Name())
	}
}

// Encap is a randomised algorithm to generate an ephemeral, fixed-length symmetric key (the KEM shared secret) and a fixed-length encapsulation of that key that can be decapsulated by the holder of the private key corresponding to pkR. This function can raise an EncapError on encapsulation failure.
// https://www.rfc-editor.org/rfc/rfc9180.html#section-4-2.1.2.5
func (s *DHKEMScheme[P, B, S]) Encap(receiverPublicKey *PublicKey[P, B, S], prng io.Reader) (sharedSecret []byte, ephemeralPublicKey *PublicKey[P, B, S], err error) {
	if prng == nil {
		return nil, nil, errs.NewIsNil("prng is nil")
	}

	ikmE, err := s.produceIKM(prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not produce ikm for ephemeral key")
	}
	sharedSecret, ephemeralPublicKey, err = s.EncapWithIKM(receiverPublicKey, ikmE)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "encapsulation with the provided ikm failed")
	}
	return sharedSecret, ephemeralPublicKey, nil
}

func (s *DHKEMScheme[P, B, S]) EncapWithIKM(receiverPublicKey *PublicKey[P, B, S], ikmE []byte) (sharedSecret []byte, ephemeralPublicKey *PublicKey[P, B, S], err error) {
	if receiverPublicKey == nil || ikmE == nil {
		return nil, nil, errs.WrapFailed(err, "arguments can't be nil")
	}
	if receiverPublicKey.Value().IsOpIdentity() {
		return nil, nil, errs.NewValidation("receiver public key is identity")
	}
	if !receiverPublicKey.Value().IsTorsionFree() {
		return nil, nil, errs.NewValidation("Public Key not in the prime subgroup")
	}

	ephemeralPrivateKey, ephemeralPublicKey, err := s.DeriveKeyPair(ikmE)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not generate key pair")
	}

	// TODO: different handling for x25519
	dhcPrivateKey, err := dhc.NewPrivateKey(ephemeralPrivateKey.Value())
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not create dhc private key")
	}
	dhcPublicKey, err := dhc.NewPublicKey(receiverPublicKey.Value())
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not create dhc public key")
	}
	dhKey, err := dhc.DeriveSharedSecretValue(dhcPrivateKey, dhcPublicKey)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "dh failed")
	}

	enc := ephemeralPublicKey.Value().ToUncompressed()
	pkRm := receiverPublicKey.Value().ToUncompressed()

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
		return nil, errs.NewIsNil("arguments can't be nil")
	}
	if ephemeralPublicKey.Value().IsOpIdentity() {
		return nil, errs.NewValidation("ephemeral public key is identity")
	}
	if !ephemeralPublicKey.Value().IsTorsionFree() {
		return nil, errs.NewValidation("Public Key not in the prime subgroup")
	}

	curve := algebra.StructureMustBeAs[curves.Curve[P, B, S]](ephemeralPublicKey.v.Structure())

	enc := ephemeralPublicKey.Value().ToUncompressed()

	// TODO: different handling for x25519
	dhcPrivateKey, err := dhc.NewPrivateKey(receiverPrivateKey.Value())
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create dhc private key")
	}
	dhcPublicKey, err := dhc.NewPublicKey(ephemeralPublicKey.Value())
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create dhc public key")
	}
	dhElement, err := dhc.DeriveSharedSecretValue(dhcPrivateKey, dhcPublicKey)
	if err != nil {
		return nil, errs.WrapFailed(err, "dh failed")
	}

	receiverPublicKeyValue := curve.ScalarBaseMul(receiverPrivateKey.Value())
	pkRm := receiverPublicKeyValue.ToUncompressed()
	kemContext := make([]byte, len(enc)+len(pkRm))
	copy(kemContext, enc)
	copy(kemContext[len(enc):], pkRm)

	sharedSecret = s.extractAndExpand(dhElement.Bytes(), kemContext)
	return sharedSecret, nil
}

// AuthEncap is the same as Encap(), and the outputs encode an assurance that the KEM shared secret was generated by the holder of the private key skS.
// https://www.rfc-editor.org/rfc/rfc9180.html#section-4-2.1.2.7
func (s *DHKEMScheme[P, B, S]) AuthEncap(receiverPublicKey *PublicKey[P, B, S], senderPrivateKey *PrivateKey[S], prng io.Reader) (sharedSecret []byte, ephemeralPublicKey *PublicKey[P, B, S], err error) {
	if prng == nil {
		return nil, nil, errs.NewIsNil("prng is nil")
	}

	ikmE, err := s.produceIKM(prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not produce ikm for ephemeral key")
	}

	sharedSecret, ephemeralPublicKey, err = s.AuthEncapWithIKM(receiverPublicKey, senderPrivateKey, ikmE)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "encapsulation with the provided ikm failed")
	}

	return sharedSecret, ephemeralPublicKey, nil
}

func (s *DHKEMScheme[P, B, S]) AuthEncapWithIKM(receiverPublicKey *PublicKey[P, B, S], senderPrivateKey *PrivateKey[S], ikmE []byte) (sharedSecret []byte, ephemeralPublicKey *PublicKey[P, B, S], err error) {
	if receiverPublicKey == nil || senderPrivateKey == nil || ikmE == nil {
		return nil, nil, errs.WrapFailed(err, "arguments can't be nil")
	}
	if receiverPublicKey.Value().IsOpIdentity() {
		return nil, nil, errs.NewValidation("receiver public key is identity")
	}
	if !receiverPublicKey.Value().IsTorsionFree() {
		return nil, nil, errs.NewValidation("Public Key not in the prime subgroup")
	}

	curve := algebra.StructureMustBeAs[curves.Curve[P, B, S]](receiverPublicKey.v.Structure())
	senderPublicKeyValue := curve.ScalarBaseMul(senderPrivateKey.Value())

	ephemeralPrivateKey, ephemeralPublicKey, err := s.DeriveKeyPair(ikmE)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not generate key pair")
	}

	// TODO: different handling for x25519
	dhcEphemeralPrivate, err := dhc.NewPrivateKey(ephemeralPrivateKey.Value())
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not create dhc private key")
	}
	dhcReceiverPublic, err := dhc.NewPublicKey(receiverPublicKey.Value())
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not create dhc public key")
	}
	dhcSenderPrivate, err := dhc.NewPrivateKey(senderPrivateKey.Value())
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not create dhc private key")
	}

	dhER, err := dhc.DeriveSharedSecretValue(dhcEphemeralPrivate, dhcReceiverPublic)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "dh between receiver and ephemeral failed")
	}

	dhSR, err := dhc.DeriveSharedSecretValue(dhcSenderPrivate, dhcReceiverPublic)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "dh between receiver and sender failed")
	}

	dhBytes := make([]byte, len(dhER.Bytes())+len(dhSR.Bytes()))
	copy(dhBytes, dhER.Bytes())
	copy(dhBytes[len(dhER.Bytes()):], dhSR.Bytes())

	enc := ephemeralPublicKey.Value().ToUncompressed()
	pkRm := receiverPublicKey.Value().ToUncompressed()
	pkSm := senderPublicKeyValue.ToUncompressed()
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
		return nil, errs.NewIsNil("arguments can't be nil")
	}
	if !senderPublicKey.Value().IsTorsionFree() {
		return nil, errs.NewValidation("Public Key not in the prime subgroup")
	}
	if !ephemeralPublicKey.Value().IsTorsionFree() {
		return nil, errs.NewValidation("Public Key not in the prime subgroup")
	}

	curve := algebra.StructureMustBeAs[curves.Curve[P, B, S]](ephemeralPublicKey.v.Structure())
	receiverPublicKeyValue := curve.ScalarBaseMul(receiverPrivateKey.Value())

	// TODO: different handling for x25519
	dhcReceiverPrivateKey, err := dhc.NewPrivateKey(receiverPrivateKey.Value())
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create dhc private key")
	}
	dhcEphemeralPublicKey, err := dhc.NewPublicKey(ephemeralPublicKey.Value())
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create dhc public key")
	}
	dhcSenderPublicKey, err := dhc.NewPublicKey(senderPublicKey.Value())
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create dhc public key")
	}

	dhRE, err := dhc.DeriveSharedSecretValue(dhcReceiverPrivateKey, dhcEphemeralPublicKey)
	if err != nil {
		return nil, errs.WrapFailed(err, "dh between receiver and ephemeral failed")
	}

	dhRS, err := dhc.DeriveSharedSecretValue(dhcReceiverPrivateKey, dhcSenderPublicKey)
	if err != nil {
		return nil, errs.WrapFailed(err, "dh between receiver and sender failed")
	}

	dhBytes := make([]byte, len(dhRE.Bytes())+len(dhRS.Bytes()))
	copy(dhBytes, dhRE.Bytes())
	copy(dhBytes[len(dhRE.Bytes()):], dhRS.Bytes())

	enc := ephemeralPublicKey.Value().ToUncompressed()
	pkRm := receiverPublicKeyValue.ToUncompressed()
	pkSm := senderPublicKey.Value().ToUncompressed()
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
		return nil, errs.WrapRandomSample(err, "could not produce ikm")
	}
	return ikm, nil
}
