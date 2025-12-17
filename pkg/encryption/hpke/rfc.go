// This file contains the RFC 9180 API for HPKE (Hybrid Public Key Encryption).
// These functions correspond directly to the algorithms defined in the RFC:
//
//   - SetupBaseS/SetupBaseR: Base mode (mode_base = 0x00)
//   - SetupPSKS/SetupPSKR: PSK mode (mode_psk = 0x01)
//   - SetupAuthS/SetupAuthR: Auth mode (mode_auth = 0x02)
//   - SetupAuthPSKS/SetupAuthPSKR: AuthPSK mode (mode_auth_psk = 0x03)
//
// Each Setup function returns a context that can be used for encryption (sender)
// or decryption (receiver). The context provides Seal/Open methods for AEAD
// operations and Export for deriving additional secrets.
//
// See: https://www.rfc-editor.org/rfc/rfc9180.html#section-5

package hpke

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/encryption/hpke/internal"
)

// SetupBaseS establishes an encryption context for Base mode (mode_base = 0x00).
// This mode provides encryption to a public key without sender authentication.
//
// Parameters:
//   - suite: The cipher suite specifying KEM, KDF, and AEAD algorithms
//   - receiverPublicKey: The recipient's public key (pkR)
//   - info: Application-supplied information (optional; default "")
//   - prng: Source of randomness for ephemeral key generation
//
// Returns a SenderContext containing the capsule (enc) to send to the receiver.
//
// See: https://www.rfc-editor.org/rfc/rfc9180.html#section-5.1.1
func SetupBaseS[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](suite *CipherSuite, receiverPublicKey *PublicKey[P, B, S], info []byte, prng io.Reader) (sender *SenderContext[P, B, S], err error) {
	out, err := internal.NewSenderContext(Base, suite, receiverPublicKey, nil, info, nil, nil, prng)
	if err != nil {
		return nil, errs2.Wrap(err)
	}
	return out, nil
}

// SetupBaseR establishes a decryption context for Base mode (mode_base = 0x00).
// This is the receiver-side counterpart to SetupBaseS.
//
// Parameters:
//   - suite: The cipher suite (must match sender's)
//   - receiverPrivatekey: The recipient's private key (skR)
//   - ephemeralPublicKey: The capsule (enc) received from the sender
//   - info: Application-supplied information (must match sender's)
//
// See: https://www.rfc-editor.org/rfc/rfc9180.html#section-5.1.1
func SetupBaseR[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](suite *CipherSuite, receiverPrivatekey *PrivateKey[S], ephemeralPublicKey *PublicKey[P, B, S], info []byte) (*ReceiverContext[P, B, S], error) {
	out, err := internal.NewReceiverContext(Base, suite, receiverPrivatekey, ephemeralPublicKey, nil, info, nil, nil)
	if err != nil {
		return nil, errs2.Wrap(err)
	}
	return out, nil
}

// SetupPSKS establishes an encryption context for PSK mode (mode_psk = 0x01).
// This mode authenticates the sender via a pre-shared key known to both parties.
//
// The PSK provides authentication: the receiver can verify the sender possessed
// the PSK, but compromise of the PSK allows impersonation.
//
// Parameters:
//   - suite: The cipher suite specifying KEM, KDF, and AEAD algorithms
//   - receiverPublicKey: The recipient's public key (pkR)
//   - psk: The pre-shared key (MUST have at least 32 bytes of entropy)
//   - pskId: Identifier for the PSK (used to select among multiple PSKs)
//   - info: Application-supplied information (optional; default "")
//   - prng: Source of randomness for ephemeral key generation
//
// See: https://www.rfc-editor.org/rfc/rfc9180.html#section-5.1.2
func SetupPSKS[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](suite *CipherSuite, receiverPublicKey *PublicKey[P, B, S], psk, pskId, info []byte, prng io.Reader) (sender *SenderContext[P, B, S], err error) {
	out, err := internal.NewSenderContext(PSk, suite, receiverPublicKey, nil, info, psk, pskId, prng)
	if err != nil {
		return nil, errs2.Wrap(err)
	}
	return out, nil
}

// SealPSK encrypts a plaintext using a PSK-mode sender context.
// This is a convenience wrapper around ctx.Seal for PSK mode.
//
// See: https://www.rfc-editor.org/rfc/rfc9180.html#section-5.2
func SealPSK[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](ctx *SenderContext[P, B, S], additionalData, plaintext []byte) (ciphertext []byte, err error) {
	out, err := ctx.Seal(plaintext, additionalData)
	if err != nil {
		return nil, errs2.Wrap(err)
	}
	return out, nil
}

// SetupPSKR establishes a decryption context for PSK mode (mode_psk = 0x01).
// This is the receiver-side counterpart to SetupPSKS.
//
// Parameters:
//   - suite: The cipher suite (must match sender's)
//   - receiverPrivatekey: The recipient's private key (skR)
//   - ephemeralPublicKey: The capsule (enc) received from the sender
//   - psk: The pre-shared key (must match sender's)
//   - pskId: Identifier for the PSK (must match sender's)
//   - info: Application-supplied information (must match sender's)
//
// See: https://www.rfc-editor.org/rfc/rfc9180.html#section-5.1.2
func SetupPSKR[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](suite *CipherSuite, receiverPrivatekey *PrivateKey[S], ephemeralPublicKey *PublicKey[P, B, S], psk, pskId, info []byte) (*ReceiverContext[P, B, S], error) {
	out, err := internal.NewReceiverContext(PSk, suite, receiverPrivatekey, ephemeralPublicKey, nil, info, psk, pskId)
	if err != nil {
		return nil, errs2.Wrap(err)
	}
	return out, nil
}

// SetupAuthS establishes an encryption context for Auth mode (mode_auth = 0x02).
// This mode authenticates the sender via an asymmetric key pair, allowing the
// recipient to verify the sender possessed the corresponding private key.
//
// Unlike PSK mode, Auth mode provides non-repudiation: only the holder of skS
// could have created the ciphertext. However, it requires the receiver to know
// the sender's public key in advance.
//
// Parameters:
//   - suite: The cipher suite specifying KEM, KDF, and AEAD algorithms
//   - receiverPublicKey: The recipient's public key (pkR)
//   - senderPrivateKey: The sender's private key (skS) for authentication
//   - info: Application-supplied information (optional; default "")
//   - prng: Source of randomness for ephemeral key generation
//
// See: https://www.rfc-editor.org/rfc/rfc9180.html#section-5.1.3
func SetupAuthS[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](suite *CipherSuite, receiverPublicKey *PublicKey[P, B, S], senderPrivateKey *PrivateKey[S], info []byte, prng io.Reader) (sender *SenderContext[P, B, S], err error) {
	out, err := internal.NewSenderContext(Auth, suite, receiverPublicKey, senderPrivateKey, info, nil, nil, prng)
	if err != nil {
		return nil, errs2.Wrap(err)
	}
	return out, nil
}

// SetupAuthR establishes a decryption context for Auth mode (mode_auth = 0x02).
// This is the receiver-side counterpart to SetupAuthS.
//
// The receiver uses the sender's public key to verify the sender's identity.
// Decryption will fail if the ciphertext was not created using the corresponding
// sender private key.
//
// Parameters:
//   - suite: The cipher suite (must match sender's)
//   - receiverPrivatekey: The recipient's private key (skR)
//   - ephemeralPublicKey: The capsule (enc) received from the sender
//   - senderPublicKey: The sender's public key (pkS) for authentication
//   - info: Application-supplied information (must match sender's)
//
// See: https://www.rfc-editor.org/rfc/rfc9180.html#section-5.1.3
func SetupAuthR[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](suite *CipherSuite, receiverPrivatekey *PrivateKey[S], ephemeralPublicKey, senderPublicKey *PublicKey[P, B, S], info []byte) (*ReceiverContext[P, B, S], error) {
	out, err := internal.NewReceiverContext(Auth, suite, receiverPrivatekey, ephemeralPublicKey, senderPublicKey, info, nil, nil)
	if err != nil {
		return nil, errs2.Wrap(err)
	}
	return out, nil
}

// SetupAuthPSKS establishes an encryption context for AuthPSK mode (mode_auth_psk = 0x03).
// This mode combines both PSK and asymmetric authentication, providing defence in depth.
//
// The sender is authenticated via both mechanisms: the PSK is incorporated into the
// key schedule, and the sender's private key is used in the encapsulation. Both must
// be valid for decryption to succeed.
//
// Parameters:
//   - suite: The cipher suite specifying KEM, KDF, and AEAD algorithms
//   - receiverPublicKey: The recipient's public key (pkR)
//   - senderPrivateKey: The sender's private key (skS) for authentication
//   - psk: The pre-shared key (MUST have at least 32 bytes of entropy)
//   - pskId: Identifier for the PSK
//   - info: Application-supplied information (optional; default "")
//   - prng: Source of randomness for ephemeral key generation
//
// See: https://www.rfc-editor.org/rfc/rfc9180.html#section-5.1.4
func SetupAuthPSKS[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](suite *CipherSuite, receiverPublicKey *PublicKey[P, B, S], senderPrivateKey *PrivateKey[S], psk, pskId, info []byte, prng io.Reader) (sender *SenderContext[P, B, S], err error) {
	out, err := internal.NewSenderContext(AuthPSk, suite, receiverPublicKey, senderPrivateKey, info, psk, pskId, prng)
	if err != nil {
		return nil, errs2.Wrap(err)
	}
	return out, nil
}

// SetupAuthPSKR establishes a decryption context for AuthPSK mode (mode_auth_psk = 0x03).
// This is the receiver-side counterpart to SetupAuthPSKS.
//
// Both the sender's public key and the PSK are verified during decryption. The
// decryption will fail if either authentication mechanism fails.
//
// Parameters:
//   - suite: The cipher suite (must match sender's)
//   - receiverPrivatekey: The recipient's private key (skR)
//   - ephemeralPublicKey: The capsule (enc) received from the sender
//   - senderPublicKey: The sender's public key (pkS) for authentication
//   - psk: The pre-shared key (must match sender's)
//   - pskId: Identifier for the PSK (must match sender's)
//   - info: Application-supplied information (must match sender's)
//
// See: https://www.rfc-editor.org/rfc/rfc9180.html#section-5.1.4
func SetupAuthPSKR[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](suite *CipherSuite, receiverPrivatekey *PrivateKey[S], ephemeralPublicKey, senderPublicKey *PublicKey[P, B, S], psk, pskId, info []byte) (*ReceiverContext[P, B, S], error) {
	out, err := internal.NewReceiverContext(AuthPSk, suite, receiverPrivatekey, ephemeralPublicKey, senderPublicKey, info, psk, pskId)
	if err != nil {
		return nil, errs2.Wrap(err)
	}
	return out, nil
}
