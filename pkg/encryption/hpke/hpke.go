package hpke

import (
	"crypto/cipher"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/errs-go/pkg/errs"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
	"github.com/bronlabs/bron-crypto/pkg/encryption/hpke/internal"
)

type (
	// ModeID is a one-byte value indicating the HPKE mode, defined in RFC 9180 Table 1.
	// The four modes provide different authentication guarantees:
	//   - Base (0x00): No sender authentication
	//   - PSK (0x01): Sender authenticated via pre-shared key
	//   - Auth (0x02): Sender authenticated via asymmetric key
	//   - AuthPSK (0x03): Sender authenticated via both PSK and asymmetric key
	//
	// See: https://www.rfc-editor.org/rfc/rfc9180.html#section-5
	ModeID = internal.ModeID

	// AEADID is a two-byte value identifying the AEAD algorithm, defined in RFC 9180 Table 3.
	// HPKE supports AES-128-GCM, AES-256-GCM, ChaCha20Poly1305, and an export-only mode.
	//
	// See: https://www.rfc-editor.org/rfc/rfc9180.html#section-7.3
	AEADID = internal.AEADID

	// KDFID is a two-byte value identifying the key derivation function, defined in RFC 9180 Table 2.
	// HPKE uses HKDF with either SHA-256 or SHA-512 as the underlying hash.
	//
	// See: https://www.rfc-editor.org/rfc/rfc9180.html#section-7.2
	KDFID = internal.KDFID

	// KEMID is a two-byte value identifying the key encapsulation mechanism, defined in RFC 9180 Table 2.
	// This implementation supports DHKEM(P-256, HKDF-SHA256) and DHKEM(X25519, HKDF-SHA256).
	//
	// See: https://www.rfc-editor.org/rfc/rfc9180.html#section-7.1
	KEMID = internal.KEMID

	// PrivateKey represents a KEM private key, which is a scalar in the underlying elliptic curve's
	// scalar field. The private key is used for decapsulation and, in authenticated modes, to prove
	// the sender's identity.
	PrivateKey[S algebra.PrimeFieldElement[S]] = internal.PrivateKey[S]

	// PublicKey represents a KEM public key, which is a point on the underlying elliptic curve.
	// The public key is used for encapsulation and to identify the recipient.
	PublicKey[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]] = internal.PublicKey[P, B, S]

	// Capsule is the encapsulated key transmitted from sender to receiver, represented as an
	// ephemeral public key. In DHKEM, the capsule is the serialised ephemeral public key (enc)
	// that allows the receiver to derive the same shared secret.
	//
	// See: https://www.rfc-editor.org/rfc/rfc9180.html#section-4.1
	Capsule[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]] = internal.PublicKey[P, B, S]

	// Ciphertext is the encrypted message produced by HPKE's AEAD encryption.
	// It contains both the encrypted plaintext and the authentication tag.
	Ciphertext []byte

	// Message is the plaintext input to or output from HPKE encryption/decryption.
	Message = []byte

	// CipherSuite specifies the combination of KEM, KDF, and AEAD algorithms used for HPKE.
	// The suite identifier is computed as concat("HPKE", I2OSP(kem_id, 2), I2OSP(kdf_id, 2), I2OSP(aead_id, 2)).
	//
	// See: https://www.rfc-editor.org/rfc/rfc9180.html#section-5.1
	CipherSuite = internal.CipherSuite

	// SenderContext holds the encryption context established by the sender after key encapsulation.
	// It provides the Seal method for encrypting messages and Export for deriving additional secrets.
	// The context maintains sequence numbers to ensure unique nonces for each encryption operation.
	//
	// See: https://www.rfc-editor.org/rfc/rfc9180.html#section-5.2
	SenderContext[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]] = internal.SenderContext[P, B, S]

	// ReceiverContext holds the decryption context established by the receiver after key decapsulation.
	// It provides the Open method for decrypting messages and Export for deriving additional secrets.
	// The context maintains sequence numbers that must match the sender's for successful decryption.
	//
	// See: https://www.rfc-editor.org/rfc/rfc9180.html#section-5.2
	ReceiverContext[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]] = internal.ReceiverContext[P, B, S]
)

const (
	// Name is the identifier for the HPKE encryption scheme.
	Name encryption.Name = "HPKE"

	// HPKE Modes (RFC 9180 Section 5, Table 1)
	// These modes determine the authentication properties of the HPKE context.

	// Base mode (mode_base = 0x00) provides encryption without sender authentication.
	// The recipient cannot verify the sender's identity.
	Base ModeID = internal.Base

	// PSk mode (mode_psk = 0x01) authenticates the sender via a pre-shared key.
	// Both parties must possess the same PSK and PSK ID. The recipient can verify
	// the sender possessed the PSK, but PSK compromise allows impersonation.
	PSk ModeID = internal.PSk

	// Auth mode (mode_auth = 0x02) authenticates the sender via an asymmetric key pair.
	// The sender's private key is used in the encapsulation, allowing the recipient
	// to verify the sender's identity using the sender's public key.
	Auth ModeID = internal.Auth

	// AuthPSk mode (mode_auth_psk = 0x03) combines PSK and asymmetric authentication.
	// The sender is authenticated via both mechanisms, providing defence in depth.
	AuthPSk ModeID = internal.AuthPSk

	// AEAD Algorithm Identifiers (RFC 9180 Section 7.3, Table 3).

	// AEAD_RESERVED (0x0000) is reserved and MUST NOT be used.
	AEAD_RESERVED AEADID = internal.AEAD_RESERVED

	// AEAD_AES_128_GCM (0x0001) specifies AES-128-GCM with Nk=16, Nn=12, Nt=16.
	AEAD_AES_128_GCM AEADID = internal.AEAD_AES_128_GCM

	// AEAD_AES_256_GCM (0x0002) specifies AES-256-GCM with Nk=32, Nn=12, Nt=16.
	AEAD_AES_256_GCM AEADID = internal.AEAD_AES_256_GCM

	// AEAD_CHACHA_20_POLY_1305 (0x0003) specifies ChaCha20Poly1305 with Nk=32, Nn=12, Nt=16.
	AEAD_CHACHA_20_POLY_1305 AEADID = internal.AEAD_CHACHA_20_POLY_1305

	// AEAD_EXPORT_ONLY (0xFFFF) indicates that the AEAD is not used for encryption;
	// only the Export interface is available. This is useful for key derivation scenarios.
	AEAD_EXPORT_ONLY AEADID = internal.AEAD_EXPORT_ONLY

	// KDF Algorithm Identifiers (RFC 9180 Section 7.2, Table 2).

	// KDF_HKDF_RESERVED (0x0000) is reserved and MUST NOT be used.
	KDF_HKDF_RESERVED KDFID = internal.KDF_HKDF_RESERVED

	// KDF_HKDF_SHA256 (0x0001) specifies HKDF-SHA256 with Nh=32.
	KDF_HKDF_SHA256 KDFID = internal.KDF_HKDF_SHA256

	// KDF_HKDF_SHA512 (0x0003) specifies HKDF-SHA512 with Nh=64.
	KDF_HKDF_SHA512 KDFID = internal.KDF_HKDF_SHA512

	// KEM Algorithm Identifiers (RFC 9180 Section 7.1, Table 2).

	// DHKEM_RESERVED (0x0000) is reserved and MUST NOT be used.
	DHKEM_RESERVED KEMID = internal.DHKEM_RESERVED

	// DHKEM_P256_HKDF_SHA256 (0x0010) specifies DHKEM(P-256, HKDF-SHA256)
	// with Nsecret=32, Nenc=65, Npk=65, Nsk=32.
	DHKEM_P256_HKDF_SHA256 KEMID = internal.DHKEM_P256_HKDF_SHA256

	// DHKEM_X25519_HKDF_SHA256 (0x0020) specifies DHKEM(X25519, HKDF-SHA256)
	// with Nsecret=32, Nenc=32, Npk=32, Nsk=32.
	DHKEM_X25519_HKDF_SHA256 KEMID = internal.DHKEM_X25519_HKDF_SHA256
)

var (
	// NewCipherSuite creates a new CipherSuite from the specified KEM, KDF, and AEAD identifiers.
	// Returns an error if any identifier is reserved (0x0000) or invalid.
	//
	// See: https://www.rfc-editor.org/rfc/rfc9180.html#section-5.1
	NewCipherSuite = internal.NewCipherSuite
)

// NewScheme creates a new HPKE scheme parameterised by the given elliptic curve and cipher suite.
// The curve determines the KEM (key encapsulation mechanism), while the cipher suite specifies
// the KDF (key derivation function) and AEAD (authenticated encryption) algorithms.
//
// The scheme provides factory methods for creating encrypters, decrypters, and direct access
// to KEM/DEM operations for more advanced use cases.
//
// See: https://www.rfc-editor.org/rfc/rfc9180.html
func NewScheme[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](curve curves.Curve[P, B, S], cipherSuite *CipherSuite) (*Scheme[P, B, S], error) {
	if curve == nil {
		return nil, ErrInvalidArgument.WithStackFrame()
	}
	if cipherSuite == nil {
		return nil, ErrInvalidArgument.WithStackFrame()
	}
	kdf, err := internal.NewKDF(cipherSuite.KDFID())
	if err != nil {
		return nil, errs.Wrap(err)
	}
	dhkem, err := internal.NewDHKEM(curve, kdf)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	aead, err := internal.NewAEAD(cipherSuite.AEADID())
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return &Scheme[P, B, S]{
		curve:       curve,
		kdf:         kdf,
		dhkem:       dhkem,
		aead:        aead,
		cipherSuite: cipherSuite,
	}, nil
}

// Scheme is the main HPKE scheme type, parameterised by the elliptic curve point type.
// It combines a KEM, KDF, and AEAD to provide hybrid public-key encryption as specified
// in RFC 9180. The scheme supports all four HPKE modes: Base, PSK, Auth, and AuthPSK.
type Scheme[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	curve       curves.Curve[P, B, S]
	kdf         *internal.KDFScheme
	dhkem       *internal.DHKEMScheme[P, B, S]
	aead        *internal.AEADScheme
	cipherSuite *CipherSuite
}

// Name returns the scheme identifier "HPKE".
func (*Scheme[P, B, S]) Name() encryption.Name {
	return Name
}

// KEM returns a key encapsulation mechanism instance for this scheme.
// In HPKE, the KEM is used to establish a shared secret between sender and receiver.
// Use WithSenderPrivateKey option to enable authenticated encapsulation (Auth mode).
//
// See: https://www.rfc-editor.org/rfc/rfc9180.html#section-4
func (s *Scheme[P, B, S]) KEM(opts ...encryption.KEMOption[*KEM[P, B, S], *PublicKey[P, B, S], *Capsule[P, B, S]]) (*KEM[P, B, S], error) {
	kem := &KEM[P, B, S]{
		v:                s.dhkem,
		senderPrivateKey: nil,
	}

	for _, opt := range opts {
		if err := opt(kem); err != nil {
			return nil, errs.Wrap(err)
		}
	}

	return kem, nil
}

// DEM returns a data encapsulation mechanism instance for this scheme.
// The DEM uses the receiver's private key to decapsulate the shared secret from a capsule.
// Use WithSenderPublicKey option to enable authenticated decapsulation (Auth mode).
//
// See: https://www.rfc-editor.org/rfc/rfc9180.html#section-4
func (s *Scheme[P, B, S]) DEM(receiverPrivateKey *PrivateKey[S], opts ...encryption.DEMOption[*DEM[P, B, S], *Capsule[P, B, S]]) (*DEM[P, B, S], error) {
	if receiverPrivateKey == nil {
		return nil, ErrInvalidArgument.WithStackFrame()
	}
	dem := &DEM[P, B, S]{
		v:                  s.dhkem,
		receiverPrivateKey: receiverPrivateKey,
		senderPublicKey:    nil,
	}
	for _, opt := range opts {
		if err := opt(dem); err != nil {
			return nil, errs.Wrap(err)
		}
	}
	return dem, nil
}

// AEAD returns an AEAD cipher instance initialised with the given symmetric key.
// This provides direct access to the underlying AEAD algorithm (AES-GCM or ChaCha20Poly1305)
// for use cases requiring manual key management outside the standard HPKE flow.
func (s *Scheme[P, B, S]) AEAD(key *encryption.SymmetricKey) (cipher.AEAD, error) {
	if key == nil {
		return nil, ErrInvalidArgument.WithStackFrame()
	}
	out, err := s.aead.New(key.Bytes())
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return out, nil
}

// CipherSuite returns the cipher suite used by this scheme.
func (s *Scheme[P, B, S]) CipherSuite() *CipherSuite {
	return s.cipherSuite
}

// Keygen creates a key generator for this HPKE scheme.
// The key generator produces key pairs compatible with the scheme's KEM algorithm.
// Key generation follows RFC 9180 Section 4, using DeriveKeyPair with random IKM.
//
// See: https://www.rfc-editor.org/rfc/rfc9180.html#section-4
func (s *Scheme[P, B, S]) Keygen(opts ...KeyGeneratorOption[P, B, S]) (*KeyGenerator[P, B, S], error) {
	kg := &KeyGenerator[P, B, S]{
		dhkem: s.dhkem,
	}
	for _, opt := range opts {
		if err := opt(kg); err != nil {
			return nil, errs.Wrap(err)
		}
	}
	return kg, nil
}

// Encrypter creates an HPKE encrypter that can seal messages to a recipient's public key.
// The encrypter establishes a fresh sender context for each encryption, unless caching
// is enabled via EncryptingWhileCachingRecentContextualInfo.
//
// Available options configure the HPKE mode:
//   - EncryptingWithApplicationInfo: Set application-specific info parameter
//   - EncryptingWithAuthentication: Enable Auth mode with sender's private key
//   - EncryptingWithPreSharedKey: Enable PSK mode with pre-shared key
//   - EncryptingWithAuthPSK: Enable AuthPSK mode with both
//   - EncryptingWhileCachingRecentContextualInfo: Cache context for Export
//
// See: https://www.rfc-editor.org/rfc/rfc9180.html#section-6
func (s *Scheme[P, B, S]) Encrypter(opts ...encryption.EncrypterOption[*Encrypter[P, B, S], *PublicKey[P, B, S], Message, Ciphertext, *Capsule[P, B, S]]) (*Encrypter[P, B, S], error) {
	encrypter := &Encrypter[P, B, S]{ //nolint:exhaustruct // set later and/or by options.
		suite: s.cipherSuite,
	}
	for _, opt := range opts {
		if err := opt(encrypter); err != nil {
			return nil, errs.Wrap(err)
		}
	}
	return encrypter, nil
}

// Decrypter creates an HPKE decrypter that can open messages encrypted to the receiver's public key.
// The decrypter requires the receiver's private key and the capsule (ephemeral public key) from
// the sender. The receiver context is established during construction based on the configured mode.
//
// Required option:
//   - DecryptingWithCapsule: The capsule (enc) received from the sender
//
// Mode-specific options:
//   - DecryptingWithApplicationInfo: Set application-specific info parameter (must match sender)
//   - DecryptingWithAuthentication: Enable Auth mode with sender's public key
//   - DecryptingWithPreSharedKey: Enable PSK mode with pre-shared key
//   - DecryptingWithAuthPSK: Enable AuthPSK mode with both
//
// See: https://www.rfc-editor.org/rfc/rfc9180.html#section-6
func (s *Scheme[P, B, S]) Decrypter(receiverPrivateKey *PrivateKey[S], opts ...encryption.DecrypterOption[*Decrypter[P, B, S], Message, Ciphertext]) (*Decrypter[P, B, S], error) {
	if receiverPrivateKey == nil {
		return nil, ErrInvalidArgument.WithStackFrame()
	}
	decrypter := &Decrypter[P, B, S]{ //nolint:exhaustruct // set later and/or by options.
		suite:      s.cipherSuite,
		privateKey: receiverPrivateKey,
	}
	for _, opt := range opts {
		if err := opt(decrypter); err != nil {
			return nil, errs.Wrap(err)
		}
	}
	if decrypter.ephemeralPublicKey == nil {
		return nil, errs.New("capsule (ephemeral public key) must be provided")
	}
	var ctx *ReceiverContext[P, B, S]
	var err error
	switch decrypter.Mode() {
	case Base:
		ctx, err = SetupBaseR(s.cipherSuite, receiverPrivateKey, decrypter.ephemeralPublicKey, decrypter.info)
	case PSk:
		ctx, err = SetupPSKR(s.cipherSuite, receiverPrivateKey, decrypter.ephemeralPublicKey, decrypter.psk.Bytes(), decrypter.pskID, decrypter.info)
	case Auth:
		ctx, err = SetupAuthR(s.cipherSuite, receiverPrivateKey, decrypter.ephemeralPublicKey, decrypter.senderPublicKey, decrypter.info)
	case AuthPSk:
		ctx, err = SetupAuthPSKR(s.cipherSuite, receiverPrivateKey, decrypter.ephemeralPublicKey, decrypter.senderPublicKey, decrypter.psk.Bytes(), decrypter.pskID, decrypter.info)
	default:
		return nil, ErrNotSupported.WithMessage("HPKE mode")
	}
	if err != nil {
		return nil, errs.Wrap(err)
	}
	decrypter.ctx = ctx
	return decrypter, nil
}

// Equal reports whether both ciphertexts are equal.
func (c Ciphertext) Equal(other Ciphertext) bool {
	return ct.SliceEqual([]byte(c), []byte(other)) == ct.True
}
