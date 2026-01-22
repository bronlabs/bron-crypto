package hpke

import (
	"io"
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
	"github.com/bronlabs/bron-crypto/pkg/encryption/hpke/internal"
	"github.com/bronlabs/errs-go/pkg/errs"
)

// KeyGeneratorOption is a functional option for configuring the HPKE key generator.
// Currently no options are defined as HPKE key generation is fully determined by the
// cipher suite's KEM algorithm.
type KeyGeneratorOption[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]] = encryption.KeyGeneratorOption[*KeyGenerator[P, B, S], *PrivateKey[S], *PublicKey[P, B, S]]

// KeyGenerator generates HPKE key pairs for the configured cipher suite.
// Key generation follows the DeriveKeyPair algorithm defined in RFC 9180 Section 4,
// which uses the KEM's KDF to derive keys from random input keying material (IKM).
//
// See: https://www.rfc-editor.org/rfc/rfc9180.html#section-4
type KeyGenerator[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	dhkem *internal.DHKEMScheme[P, B, S]
}

// Generate creates a new HPKE key pair using randomness from prng.
// The private key is derived using the KEM's DeriveKeyPair algorithm with random IKM.
// The public key is the corresponding curve point pk = sk * G.
//
// See: https://www.rfc-editor.org/rfc/rfc9180.html#section-4
func (kg *KeyGenerator[P, B, S]) Generate(prng io.Reader) (sk *PrivateKey[S], pk *PublicKey[P, B, S], err error) {
	if prng == nil {
		return nil, nil, ErrInvalidArgument.WithStackFrame().WithMessage("prng is nil")
	}
	sk, pk, err = kg.dhkem.GenerateKeyPair(prng)
	if err != nil {
		return nil, nil, errs.Wrap(err)
	}
	return sk, pk, nil
}

// GenerateWithSeed creates a new HPKE key pair deterministically from seed material.
// The seed (IKM) SHOULD have at least Nsk bytes of entropy for the KEM algorithm.
// This implements the DeriveKeyPair algorithm from RFC 9180 Section 4.
//
// See: https://www.rfc-editor.org/rfc/rfc9180.html#name-derivekeypair
func (kg *KeyGenerator[P, B, S]) GenerateWithSeed(ikm []byte) (sk *PrivateKey[S], pk *PublicKey[P, B, S], err error) {
	if ikm == nil {
		return nil, nil, ErrInvalidArgument.WithStackFrame().WithMessage("ikm is nil")
	}
	sk, pk, err = kg.dhkem.DeriveKeyPair(ikm)
	if err != nil {
		return nil, nil, errs.Wrap(err)
	}
	return sk, pk, nil
}

// EncryptingWhileCachingRecentContextualInfo returns an option that enables caching
// of the sender context after encryption. This allows the Export method to be called
// to derive additional secrets from the encryption context.
//
// Note: When caching is enabled, the encrypter holds a mutex during Seal operations
// for thread safety.
func EncryptingWhileCachingRecentContextualInfo[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]]() encryption.EncrypterOption[*Encrypter[P, B, S], *PublicKey[P, B, S], Message, Ciphertext, *Capsule[P, B, S]] {
	return func(e *Encrypter[P, B, S]) error {
		e.shouldCacheCtx = true
		return nil
	}
}

// EncryptingWithApplicationInfo returns an option that sets the application-specific
// info parameter for the HPKE key schedule. The info parameter is bound to the derived
// keys and must match between sender and receiver for successful decryption.
//
// Per RFC 9180 Section 5.1, info is application-supplied information that should be
// independently agreed upon by both parties.
//
// See: https://www.rfc-editor.org/rfc/rfc9180.html#section-5.1
func EncryptingWithApplicationInfo[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](info []byte) encryption.EncrypterOption[*Encrypter[P, B, S], *PublicKey[P, B, S], Message, Ciphertext, *Capsule[P, B, S]] {
	return func(e *Encrypter[P, B, S]) error {
		e.info = info
		return nil
	}
}

// EncryptingWithAuthentication returns an option that enables Auth mode (mode_auth = 0x02).
// The sender's private key is used in the encapsulation to authenticate the sender's identity.
// The recipient can verify the sender possessed the corresponding private key.
//
// See: https://www.rfc-editor.org/rfc/rfc9180.html#section-5.1.3
func EncryptingWithAuthentication[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](sk *PrivateKey[S]) encryption.EncrypterOption[*Encrypter[P, B, S], *PublicKey[P, B, S], Message, Ciphertext, *Capsule[P, B, S]] {
	return func(e *Encrypter[P, B, S]) error {
		e.senderPrivateKey = sk
		return nil
	}
}

// EncryptingWithPreSharedKey returns an option that enables PSK mode (mode_psk = 0x01).
// Both sender and receiver must possess the same pre-shared key (psk) and PSK identifier
// (pskID). The PSK is incorporated into the key schedule, providing sender authentication.
//
// Per RFC 9180, the psk MUST have at least 32 bytes of entropy, and pskID is a sequence
// of bytes used to identify the PSK.
//
// See: https://www.rfc-editor.org/rfc/rfc9180.html#section-5.1.2
func EncryptingWithPreSharedKey[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](pskID []byte, psk *encryption.SymmetricKey) encryption.EncrypterOption[*Encrypter[P, B, S], *PublicKey[P, B, S], Message, Ciphertext, *Capsule[P, B, S]] {
	return func(e *Encrypter[P, B, S]) error {
		e.pskID = pskID
		e.psk = psk
		return nil
	}
}

// EncryptingWithAuthPSK returns an option that enables AuthPSK mode (mode_auth_psk = 0x03).
// This combines both asymmetric authentication (via the sender's private key) and PSK
// authentication, providing defence in depth.
//
// See: https://www.rfc-editor.org/rfc/rfc9180.html#section-5.1.4
func EncryptingWithAuthPSK[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](sk *PrivateKey[S], pskID []byte, psk *encryption.SymmetricKey) encryption.EncrypterOption[*Encrypter[P, B, S], *PublicKey[P, B, S], Message, Ciphertext, *Capsule[P, B, S]] {
	return func(e *Encrypter[P, B, S]) error {
		e.senderPrivateKey = sk
		e.pskID = pskID
		e.psk = psk
		return nil
	}
}

// Encrypter performs HPKE encryption operations. It establishes a sender context
// for each encryption and seals messages using the AEAD algorithm specified in
// the cipher suite.
//
// The encrypter supports all four HPKE modes, determined by which options were
// provided during construction. For each Encrypt/Seal call, a new ephemeral key
// pair is generated and a fresh sender context is established.
type Encrypter[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	suite            *CipherSuite
	senderPrivateKey *PrivateKey[S]
	info             []byte
	pskID            []byte
	psk              *encryption.SymmetricKey

	shouldCacheCtx bool
	cachedCtx      *SenderContext[P, B, S]
	mu             sync.Mutex
}

// Mode returns the HPKE mode that will be used for encryption, determined by
// which authentication parameters have been configured.
func (e *Encrypter[P, B, S]) Mode() ModeID {
	if e.psk != nil && len(e.pskID) > 0 {
		if e.senderPrivateKey != nil {
			return AuthPSk
		}
		return PSk
	}
	if e.senderPrivateKey != nil {
		return Auth
	}
	return Base
}

// Encrypt encrypts a plaintext message to the receiver's public key.
// It returns the ciphertext and the capsule (ephemeral public key) that must be
// transmitted to the receiver for decryption. This is equivalent to Seal with nil aad.
//
// A fresh sender context is established for each call, generating a new ephemeral
// key pair and deriving fresh encryption keys.
func (e *Encrypter[P, B, S]) Encrypt(plaintext Message, receiver *PublicKey[P, B, S], prng io.Reader) (Ciphertext, *Capsule[P, B, S], error) {
	return e.Seal(plaintext, receiver, nil, prng)
}

// Seal encrypts a plaintext message with associated data to the receiver's public key.
// The associated data (aad) is authenticated but not encrypted; it must be provided
// identically during decryption.
//
// Returns the ciphertext (containing encrypted plaintext and authentication tag) and
// the capsule (ephemeral public key) needed for decryption.
//
// See: https://www.rfc-editor.org/rfc/rfc9180.html#section-5.2
func (e *Encrypter[P, B, S]) Seal(plaintext Message, receiver *PublicKey[P, B, S], aad []byte, prng io.Reader) (Ciphertext, *Capsule[P, B, S], error) {
	if e.shouldCacheCtx {
		e.mu.Lock()
		defer e.mu.Unlock()
	}
	if receiver == nil {
		return nil, nil, ErrInvalidArgument.WithStackFrame().WithMessage("receiver public key is nil")
	}
	if prng == nil {
		return nil, nil, ErrInvalidArgument.WithStackFrame().WithMessage("prng is nil")
	}

	var ctx *SenderContext[P, B, S]
	var err error
	switch e.Mode() {
	case Base:
		ctx, err = SetupBaseS(e.suite, receiver, e.info, prng)
	case Auth:
		ctx, err = SetupAuthS(e.suite, receiver, e.senderPrivateKey, e.info, prng)
	case PSk:
		ctx, err = SetupPSKS(e.suite, receiver, e.psk.Bytes(), e.pskID, e.info, prng)
	case AuthPSk:
		ctx, err = SetupAuthPSKS(e.suite, receiver, e.senderPrivateKey, e.psk.Bytes(), e.pskID, e.info, prng)
	default:
		return nil, nil, ErrNotSupported.WithStackFrame().WithMessage("unsupported mode")
	}
	if err != nil {
		return nil, nil, errs.Wrap(err)
	}
	if e.shouldCacheCtx {
		e.cachedCtx = ctx
	}

	ct, err := ctx.Seal(plaintext, aad)
	if err != nil {
		return nil, nil, errs.Wrap(err)
	}
	return Ciphertext(ct), ctx.Capsule, nil
}

// Export derives a secret from the encryption context using the HPKE secret export
// mechanism. This requires context caching to be enabled via EncryptingWhileCachingRecentContextualInfo.
//
// The exporter_context parameter and length are inputs to the secret derivation.
// The same inputs will produce the same output on both sender and receiver sides.
//
// See: https://www.rfc-editor.org/rfc/rfc9180.html#section-5.3
func (e *Encrypter[P, B, S]) Export(context []byte, length uint) (*encryption.SymmetricKey, error) {
	if length == 0 {
		return nil, ErrInvalidLength.WithStackFrame()
	}
	if !e.shouldCacheCtx || e.cachedCtx == nil {
		return nil, errs.New("cannot export key without cached context")
	}
	k, err := e.cachedCtx.Export(context, int(length))
	if err != nil {
		return nil, errs.Wrap(err)
	}
	out, err := encryption.NewSymmetricKey(k)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return out, nil
}

// DecryptingWithApplicationInfo returns an option that sets the application-specific
// info parameter. This must match the info used by the sender for successful decryption.
//
// See: https://www.rfc-editor.org/rfc/rfc9180.html#section-5.1
func DecryptingWithApplicationInfo[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](info []byte) encryption.DecrypterOption[*Decrypter[P, B, S], Message, Ciphertext] {
	return func(d *Decrypter[P, B, S]) error {
		d.info = info
		return nil
	}
}

// DecryptingWithCapsule returns an option that sets the capsule (enc) received from
// the sender. The capsule is the serialised ephemeral public key used in the key
// encapsulation mechanism. This option is required for decryption.
//
// See: https://www.rfc-editor.org/rfc/rfc9180.html#section-4.1
func DecryptingWithCapsule[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](capsule *Capsule[P, B, S]) encryption.DecrypterOption[*Decrypter[P, B, S], Message, Ciphertext] {
	return func(d *Decrypter[P, B, S]) error {
		// For Base/PSK modes, the capsule is the ephemeral public key
		// For Auth modes, it will be overridden by DecryptingWithAuthentication
		d.ephemeralPublicKey = capsule
		return nil
	}
}

// DecryptingWithAuthentication returns an option that enables Auth mode (mode_auth = 0x02)
// for decryption. The sender's public key is used to verify that the sender possessed
// the corresponding private key during encapsulation.
//
// See: https://www.rfc-editor.org/rfc/rfc9180.html#section-5.1.3
func DecryptingWithAuthentication[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](pk *PublicKey[P, B, S]) encryption.DecrypterOption[*Decrypter[P, B, S], Message, Ciphertext] {
	return func(d *Decrypter[P, B, S]) error {
		d.senderPublicKey = pk
		return nil
	}
}

// DecryptingWithPreSharedKey returns an option that enables PSK mode (mode_psk = 0x01)
// for decryption. The PSK and PSK ID must match those used by the sender.
//
// See: https://www.rfc-editor.org/rfc/rfc9180.html#section-5.1.2
func DecryptingWithPreSharedKey[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](pskID []byte, psk *encryption.SymmetricKey) encryption.DecrypterOption[*Decrypter[P, B, S], Message, Ciphertext] {
	return func(d *Decrypter[P, B, S]) error {
		d.pskID = pskID
		d.psk = psk
		return nil
	}
}

// DecryptingWithAuthPSK returns an option that enables AuthPSK mode (mode_auth_psk = 0x03)
// for decryption. Both the sender's public key and PSK must be provided and match those
// used by the sender.
//
// See: https://www.rfc-editor.org/rfc/rfc9180.html#section-5.1.4
func DecryptingWithAuthPSK[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](pk *PublicKey[P, B, S], pskID []byte, psk *encryption.SymmetricKey) encryption.DecrypterOption[*Decrypter[P, B, S], Message, Ciphertext] {
	return func(d *Decrypter[P, B, S]) error {
		d.senderPublicKey = pk
		d.pskID = pskID
		d.psk = psk
		return nil
	}
}

// Decrypter performs HPKE decryption operations. The receiver context is established
// during construction based on the receiver's private key and the capsule from the sender.
//
// The decrypter supports all four HPKE modes, determined by which options were provided
// during construction. The mode must match what the sender used, or decryption will fail.
type Decrypter[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	suite      *CipherSuite
	privateKey *PrivateKey[S]

	senderPublicKey    *PublicKey[P, B, S] // For Auth modes - sender's static public key
	ephemeralPublicKey *Capsule[P, B, S]   // Ephemeral public key
	info               []byte
	pskID              []byte
	psk                *encryption.SymmetricKey

	ctx *ReceiverContext[P, B, S]
}

// Mode returns the HPKE mode configured for decryption, determined by which
// authentication parameters have been set.
func (e *Decrypter[P, B, S]) Mode() ModeID {
	if e.psk != nil && len(e.pskID) > 0 {
		if e.senderPublicKey != nil {
			return AuthPSk
		}
		return PSk
	}
	if e.senderPublicKey != nil {
		return Auth
	}
	return Base
}

// Decrypt decrypts a ciphertext encrypted to this receiver's public key.
// This is equivalent to Open with nil associated data.
func (e *Decrypter[P, B, S]) Decrypt(ciphertext Ciphertext) (Message, error) {
	return e.Open(ciphertext, nil)
}

// Open decrypts a ciphertext with associated data. The associated data must match
// exactly what was provided during encryption, or the authentication will fail.
//
// The sequence number is incremented after each successful decryption, so ciphertexts
// must be opened in the same order they were sealed by the sender.
//
// See: https://www.rfc-editor.org/rfc/rfc9180.html#section-5.2
func (e *Decrypter[P, B, S]) Open(ciphertext Ciphertext, aad []byte) (Message, error) {
	if ciphertext == nil {
		return nil, ErrInvalidArgument.WithStackFrame().WithMessage("ciphertext is nil")
	}
	pt, err := e.ctx.Open([]byte(ciphertext), aad)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return pt, nil
}

// Export derives a secret from the decryption context using the HPKE secret export
// mechanism. The exporter_context parameter and length are inputs to the secret derivation.
//
// When called with the same inputs on both sender and receiver, Export produces the
// same output, enabling key agreement for additional symmetric keys.
//
// See: https://www.rfc-editor.org/rfc/rfc9180.html#section-5.3
func (e *Decrypter[P, B, S]) Export(context []byte, length uint) (*encryption.SymmetricKey, error) {
	if length == 0 {
		return nil, ErrInvalidLength.WithStackFrame()
	}
	k, err := e.ctx.Export(context, int(length))
	if err != nil {
		return nil, errs.Wrap(err)
	}
	out, err := encryption.NewSymmetricKey(k)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return out, nil
}
