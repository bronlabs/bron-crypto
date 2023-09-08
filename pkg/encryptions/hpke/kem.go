package hpke

import (
	"encoding/binary"
	"io"

	"github.com/copperexchange/krypton/pkg/base/curves"
	"github.com/copperexchange/krypton/pkg/base/curves/curve25519"
	"github.com/copperexchange/krypton/pkg/base/curves/p256"
	"github.com/copperexchange/krypton/pkg/base/errs"
	"github.com/copperexchange/krypton/pkg/encryptions/ecies/ecsvdp/dhc"
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
	kems = map[KEMID]*DHKEMScheme{
		DHKEM_P256_HKDF_SHA256: NewP256HKDFSha256Scheme(),
	}
)

type DHKEMScheme struct {
	curve curves.Curve
	kdf   *KDFScheme
}

func NewP256HKDFSha256Scheme() *DHKEMScheme {
	return &DHKEMScheme{
		curve: p256.New(),
		kdf:   NewKDFSHA256(),
	}
}

// ID returns KEM ID as per https://www.rfc-editor.org/rfc/rfc9180.html#name-key-encapsulation-mechanism
func (s *DHKEMScheme) ID() KEMID {
	if s.curve.Name() == p256.Name {
		return DHKEM_P256_HKDF_SHA256
	}
	return DHKEM_X25519_HKDF_SHA256
}

// GenerateKeyPair is a randomised algorithm to generate a key pair.
// https://www.rfc-editor.org/rfc/rfc9180.html#section-4-2.1.2.1
func (s *DHKEMScheme) GenerateKeyPair(prng io.Reader) (*PrivateKey, error) {
	if prng == nil {
		return nil, errs.NewIsNil("prng is nil")
	}
	ikm, err := s.produceIKM(prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not produce ikm")
	}
	privateKey, err := s.DeriveKeyPair(ikm)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not produce key pair")
	}
	return privateKey, nil
}

// DeriveKeyPair is a deterministic algorithm to derive a key pair (skX, pkX) from the byte string ikm, where ikm SHOULD have at least Nsk bytes of entropy.
// https://www.rfc-editor.org/rfc/rfc9180.html#name-derivekeypair
func (s *DHKEMScheme) DeriveKeyPair(ikm []byte) (*PrivateKey, error) {
	if len(ikm) < s.NSk() {
		return nil, errs.NewInvalidLength("ikm length(=%d) < Nsk(=%d)", len(ikm), s.NSk())
	}
	switch s.curve.Name() {
	case p256.Name:
		dpkPrk := s.kdf.labeledExtract(s.suiteID(), nil, []byte("dkp_prk"), ikm)
		counter := 0
		sk := s.curve.Scalar().Zero()
		var err error
		for sk.IsZero() || err != nil {
			if counter > 255 {
				return nil, errs.NewFailed("DeriveKeyPairError")
			}
			bytes_ := s.kdf.labeledExpand(s.suiteID(), dpkPrk, []byte("candidate"), []byte{uint8(counter)}, s.NSk())
			bytes_[0] &= P256BitMask

			sk, err = s.curve.Scalar().SetBytes(bytes_)
			if err == nil {
				return &PrivateKey{
					D:         sk,
					PublicKey: s.curve.ScalarBaseMult(sk),
				}, nil
			}
			counter++
		}
	case curve25519.Name:
		// dkpPrk := labeledExtract(s.kdf.Extract, s.suiteID(), nil, []byte("dkp_prk"), ikm)
		// sk := labeledExpand(s.kdf.Expand, s.suiteID(), dkpPrk, []byte("sk"), nil, s.NSk())
		return nil, errs.NewInvalidCurve("NOT IMPLEMENTED")
	default:
		return nil, errs.NewInvalidCurve("curve %s not supported", s.curve.Name())
	}
	return nil, errs.NewFailed("couldn't derive key pair")
}

// Encap is a randomised algorithm to generate an ephemeral, fixed-length symmetric key (the KEM shared secret) and a fixed-length encapsulation of that key that can be decapsulated by the holder of the private key corresponding to pkR. This function can raise an EncapError on encapsulation failure.
// https://www.rfc-editor.org/rfc/rfc9180.html#section-4-2.1.2.5
func (s *DHKEMScheme) Encap(receiverPublicKey PublicKey, prng io.Reader) (sharedSecret []byte, ephemeralPublicKey PublicKey, err error) {
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

func (s *DHKEMScheme) EncapWithIKM(receiverPublicKey PublicKey, ikmE []byte) (sharedSecret []byte, ephemeralPublicKey PublicKey, err error) {
	if receiverPublicKey == nil || ikmE == nil {
		return nil, nil, errs.WrapFailed(err, "arguments can't be nil")
	}
	ephemeralPrivateKey, err := s.DeriveKeyPair(ikmE)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not generate key pair")
	}

	dh, err := dhc.DeriveSharedSecretValue(ephemeralPrivateKey.D, receiverPublicKey)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "dh failed")
	}

	enc := ephemeralPrivateKey.PublicKey.ToAffineUncompressed()
	pkRm := receiverPublicKey.ToAffineUncompressed()

	kemContext := make([]byte, len(enc)+len(pkRm))
	copy(kemContext, enc)
	copy(kemContext[len(enc):], pkRm)
	sharedSecret = s.extractAndExpand(dh.Bytes(), kemContext)
	return sharedSecret, ephemeralPrivateKey.PublicKey, nil
}

// Decap is a deterministic algorithm using the private key skR to recover the ephemeral symmetric key (the KEM shared secret) from its encapsulated representation enc. This function can raise a DecapError on decapsulation failure.
// https://www.rfc-editor.org/rfc/rfc9180.html#section-4-2.1.2.6
func (s *DHKEMScheme) Decap(receiverPrivateKey *PrivateKey, ephemeralPublicKey PublicKey) (sharedSecret []byte, err error) {
	if receiverPrivateKey == nil || ephemeralPublicKey == nil {
		return nil, errs.NewIsNil("arguments can't be nil")
	}
	enc := ephemeralPublicKey.ToAffineUncompressed()
	dh, err := dhc.DeriveSharedSecretValue(receiverPrivateKey.D, ephemeralPublicKey)
	if err != nil {
		return nil, errs.WrapFailed(err, "dh failed")
	}
	pkRm := receiverPrivateKey.PublicKey.ToAffineUncompressed()
	kemContext := make([]byte, len(enc)+len(pkRm))
	copy(kemContext, enc)
	copy(kemContext[len(enc):], pkRm)
	sharedSecret = s.extractAndExpand(dh.Bytes(), kemContext)
	return sharedSecret, nil
}

// AuthEncap is the same as Encap(), and the outputs encode an assurance that the KEM shared secret was generated by the holder of the private key skS.
// https://www.rfc-editor.org/rfc/rfc9180.html#section-4-2.1.2.7
func (s *DHKEMScheme) AuthEncap(receiverPublicKey PublicKey, senderPrivateKey *PrivateKey, prng io.Reader) (sharedSecret []byte, ephemeralPublicKey PublicKey, err error) {
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

func (s *DHKEMScheme) AuthEncapWithIKM(receiverPublicKey PublicKey, senderPrivateKey *PrivateKey, ikmE []byte) (sharedSecret []byte, ephemeralPublicKey PublicKey, err error) {
	if receiverPublicKey == nil || senderPrivateKey == nil || ikmE == nil {
		return nil, nil, errs.WrapFailed(err, "arguments can't be nil")
	}
	ephemeralPrivateKey, err := s.DeriveKeyPair(ikmE)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not generate key pair")
	}
	dhER, err := dhc.DeriveSharedSecretValue(ephemeralPrivateKey.D, receiverPublicKey)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "dh between receiver and ephemeral failed")
	}
	dhSR, err := dhc.DeriveSharedSecretValue(senderPrivateKey.D, receiverPublicKey)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "dh between receiver and sender failed")
	}
	dh := make([]byte, len(dhER.Bytes())+len(dhSR.Bytes()))
	copy(dh, dhER.Bytes())
	copy(dh[len(dhER.Bytes()):], dhSR.Bytes())

	enc := ephemeralPrivateKey.PublicKey.ToAffineUncompressed()
	pkRm := receiverPublicKey.ToAffineUncompressed()
	pkSm := senderPrivateKey.PublicKey.ToAffineUncompressed()
	kemContext := make([]byte, len(enc)+len(pkRm)+len(pkSm))
	copy(kemContext, enc)
	copy(kemContext[len(enc):], pkRm)
	copy(kemContext[len(enc)+len(pkRm):], pkSm)

	sharedSecret = s.extractAndExpand(dh, kemContext)
	return sharedSecret, ephemeralPrivateKey.PublicKey, nil
}

// AuthDecap is the same as Decap(), and the recipient is assured that the KEM shared secret was generated by the holder of the private key skS.
// https://www.rfc-editor.org/rfc/rfc9180.html#section-4-2.1.2.8
func (s *DHKEMScheme) AuthDecap(receiverPrivateKey *PrivateKey, senderPublicKey, ephemeralPublicKey PublicKey) (sharedSecret []byte, err error) {
	if receiverPrivateKey == nil || senderPublicKey == nil || ephemeralPublicKey == nil {
		return nil, errs.NewIsNil("arguments can't be nil")
	}
	dhRE, err := dhc.DeriveSharedSecretValue(receiverPrivateKey.D, ephemeralPublicKey)
	if err != nil {
		return nil, errs.WrapFailed(err, "dh between receiver and ephemeral failed")
	}
	dhRS, err := dhc.DeriveSharedSecretValue(receiverPrivateKey.D, senderPublicKey)
	if err != nil {
		return nil, errs.WrapFailed(err, "dh between receiver and sender failed")
	}
	dh := make([]byte, len(dhRE.Bytes())+len(dhRS.Bytes()))

	enc := ephemeralPublicKey.ToAffineUncompressed()
	pkRm := receiverPrivateKey.PublicKey.ToAffineUncompressed()
	pkSm := senderPublicKey.ToAffineUncompressed()
	kemContext := make([]byte, len(enc)+len(pkRm)+len(pkSm))
	copy(kemContext, enc)
	copy(kemContext[len(enc):], pkRm)
	copy(kemContext[len(enc)+len(pkRm):], pkSm)

	sharedSecret = s.extractAndExpand(dh, kemContext)
	return sharedSecret, nil
}

// NSecret is the length in bytes of a KEM shared secret produced by this KEM.
// https://www.rfc-editor.org/rfc/rfc9180.html#section-4-2.1.2.9
func (s *DHKEMScheme) NSecret() int {
	return nSecrets[s.ID()]
}

// NEnc is the length in bytes of an encapsulated key produced by this KEM.
// https://www.rfc-editor.org/rfc/rfc9180.html#section-4-2.1.2.10
func (s *DHKEMScheme) NEnc() int {
	return nEncs[s.ID()]
}

// NPk is the length in bytes of an encoded public key for this KEM.
// https://www.rfc-editor.org/rfc/rfc9180.html#section-4-2.1.2.11
func (s *DHKEMScheme) NPk() int {
	return nPKs[s.ID()]
}

// NSk is the length in bytes of an encoded private key for this KEM.
// https://www.rfc-editor.org/rfc/rfc9180.html#section-4-2.1.2.12
func (s *DHKEMScheme) NSk() int {
	return nSKs[s.ID()]
}

// extractAndExpand is an internal method used in other methods of DHKEM.
// https://www.rfc-editor.org/rfc/rfc9180.html#section-4.1-4
func (s *DHKEMScheme) extractAndExpand(dh, kmContext []byte) []byte {
	eaePrk := s.kdf.labeledExtract(s.suiteID(), nil, []byte("eae_prk"), dh)
	sharedSecret := s.kdf.labeledExpand(s.suiteID(), eaePrk, []byte("shared_secret"), kmContext, s.kdf.Nh())
	return sharedSecret
}

func (s *DHKEMScheme) suiteID() []byte {
	idBuffer := make([]byte, 2)
	binary.BigEndian.PutUint16(idBuffer, uint16(s.ID()))
	return append([]byte("KEM"), idBuffer...)
}

func (s *DHKEMScheme) produceIKM(prng io.Reader) ([]byte, error) {
	ikm := make([]byte, s.NSk())
	if _, err := prng.Read(ikm); err != nil {
		return nil, errs.WrapRandomSampleFailed(err, "could not produce ikm")
	}
	return ikm, nil
}
