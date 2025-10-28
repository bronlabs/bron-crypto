package hpke

import (
	"crypto/cipher"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
	"github.com/bronlabs/bron-crypto/pkg/encryption/hpke/internal"
)

type (
	ModeID = internal.ModeID
	AEADID = internal.AEADID
	KDFID  = internal.KDFID
	KEMID  = internal.KEMID

	PrivateKey[S algebra.PrimeFieldElement[S]]                                                          = internal.PrivateKey[S]
	PublicKey[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]] = internal.PublicKey[P, B, S]

	Capsule[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]] = internal.PublicKey[P, B, S]
	Ciphertext                                                                                        []byte
	Message                                                                                           = []byte

	CipherSuite                                                                                             = internal.CipherSuite
	SenderContext[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]] = internal.SenderContext[P, B, S]
	ReceiverContext                                                                                         = internal.ReceiverContext
)

const (
	Name encryption.Name = "HPKE"

	Base    ModeID = internal.Base
	PSk     ModeID = internal.PSk
	Auth    ModeID = internal.Auth
	AuthPSk ModeID = internal.AuthPSk

	AEAD_RESERVED            AEADID = internal.AEAD_RESERVED
	AEAD_AES_128_GCM         AEADID = internal.AEAD_AES_128_GCM
	AEAD_AES_256_GCM         AEADID = internal.AEAD_AES_256_GCM
	AEAD_CHACHA_20_POLY_1305 AEADID = internal.AEAD_CHACHA_20_POLY_1305
	AEAD_EXPORT_ONLY         AEADID = internal.AEAD_EXPORT_ONLY

	KDF_HKDF_RESERVED KDFID = internal.KDF_HKDF_RESERVED
	KDF_HKDF_SHA256   KDFID = internal.KDF_HKDF_SHA256
	KDF_HKDF_SHA512   KDFID = internal.KDF_HKDF_SHA512

	DHKEM_RESERVED           KEMID = internal.DHKEM_RESERVED
	DHKEM_P256_HKDF_SHA256   KEMID = internal.DHKEM_P256_HKDF_SHA256
	DHKEM_X25519_HKDF_SHA256 KEMID = internal.DHKEM_X25519_HKDF_SHA256
)

var (
	NewCipherSuite = internal.NewCipherSuite
)

func NewScheme[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](curve curves.Curve[P, B, S], cipherSuite *CipherSuite) (*Scheme[P, B, S], error) {
	if curve == nil {
		return nil, errs.NewIsNil("curve")
	}
	if cipherSuite == nil {
		return nil, errs.NewIsNil("cipherSuite")
	}
	kdf, err := internal.NewKDF(cipherSuite.KDFID())
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create KDF")
	}
	dhkem, err := internal.NewDHKEM(curve, kdf)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create DHKEM")
	}
	aead, err := internal.NewAEAD(cipherSuite.AEADID())
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create AEAD")
	}
	return &Scheme[P, B, S]{
		curve:       curve,
		kdf:         kdf,
		dhkem:       dhkem,
		aead:        aead,
		cipherSuite: cipherSuite,
	}, nil
}

type Scheme[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	curve       curves.Curve[P, B, S]
	kdf         *internal.KDFScheme
	dhkem       *internal.DHKEMScheme[P, B, S]
	aead        *internal.AEADScheme
	cipherSuite *CipherSuite
}

func (s *Scheme[P, B, S]) Name() encryption.Name {
	return Name
}

func (s *Scheme[P, B, S]) KEM(opts ...encryption.KEMOption[*KEM[P, B, S], *PublicKey[P, B, S], *Capsule[P, B, S]]) (*KEM[P, B, S], error) {
	kem := &KEM[P, B, S]{
		v:                s.dhkem,
		senderPrivateKey: nil,
	}

	for _, opt := range opts {
		if err := opt(kem); err != nil {
			return nil, errs.WrapFailed(err, "could not apply KEM option")
		}
	}

	return kem, nil
}

func (s *Scheme[P, B, S]) DEM(receiverPrivateKey *PrivateKey[S], opts ...encryption.DEMOption[*DEM[P, B, S], *Capsule[P, B, S]]) (*DEM[P, B, S], error) {
	if receiverPrivateKey == nil {
		return nil, errs.NewIsNil("receiverPrivateKey")
	}
	dem := &DEM[P, B, S]{
		v:                  s.dhkem,
		receiverPrivateKey: receiverPrivateKey,
		senderPublicKey:    nil,
	}
	for _, opt := range opts {
		if err := opt(dem); err != nil {
			return nil, errs.WrapFailed(err, "could not apply DEM option")
		}
	}
	return dem, nil
}

func (s *Scheme[P, B, S]) AEAD(key *encryption.SymmetricKey) (cipher.AEAD, error) {
	if key == nil {
		return nil, errs.NewIsNil("symmetric key")
	}
	return s.aead.New(key.Bytes())
}

func (s *Scheme[P, B, S]) CipherSuite() *CipherSuite {
	return s.cipherSuite
}

func (s *Scheme[P, B, S]) Encrypter(opts ...encryption.EncrypterOption[*Encrypter[P, B, S], *PublicKey[P, B, S], Message, Ciphertext, *Capsule[P, B, S]]) (*Encrypter[P, B, S], error) {
	encrypter := &Encrypter[P, B, S]{
		suite: s.cipherSuite,
	}
	for _, opt := range opts {
		if err := opt(encrypter); err != nil {
			return nil, errs.WrapFailed(err, "could not apply Encrypter option")
		}
	}
	return encrypter, nil
}

func (s *Scheme[P, B, S]) Decrypter(receiverPrivateKey *PrivateKey[S], opts ...encryption.DecrypterOption[*Decrypter[P, B, S], Message, Ciphertext]) (*Decrypter[P, B, S], error) {
	if receiverPrivateKey == nil {
		return nil, errs.NewIsNil("receiverPrivateKey")
	}
	decrypter := &Decrypter[P, B, S]{
		suite:      s.cipherSuite,
		privateKey: receiverPrivateKey,
	}
	for _, opt := range opts {
		if err := opt(decrypter); err != nil {
			return nil, errs.WrapFailed(err, "could not apply Decrypter option")
		}
	}
	var ctx *ReceiverContext
	var err error
	switch decrypter.Mode() {
	case Base:
		ctx, err = SetupBaseR(s.cipherSuite, receiverPrivateKey, decrypter.senderPublicKey, decrypter.info)
	case PSk:
		ctx, err = SetupPSKR(s.cipherSuite, receiverPrivateKey, decrypter.senderPublicKey, decrypter.psk.Bytes(), decrypter.pskId, decrypter.info)
	case Auth:
		ctx, err = SetupAuthR(s.cipherSuite, receiverPrivateKey, decrypter.senderPublicKey, decrypter.senderPublicKey, decrypter.info)
	case AuthPSk:
		ctx, err = SetupAuthPSKR(s.cipherSuite, receiverPrivateKey, decrypter.senderPublicKey, decrypter.senderPublicKey, decrypter.psk.Bytes(), decrypter.pskId, decrypter.info)
	default:
		return nil, errs.NewType("unsupported HPKE mode")
	}
	if err != nil {
		return nil, errs.WrapFailed(err, "could not setup receiver context")
	}
	decrypter.ctx = ctx
	return decrypter, nil
}
