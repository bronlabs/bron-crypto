package indcpacom

import (
	"fmt"
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	"github.com/bronlabs/bron-crypto/pkg/commitments/internal"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
)

// NewCommitmentKey builds a commitment key from a public encryption key, rejecting
// nil. The encryption key is the entire public parameter — committing encrypts
// under it. Binding does not depend on how the key was generated, but hiding holds
// only while the corresponding decryption key is unknown to the verifier.
func NewCommitmentKey[EK encryption.EncryptionKey[EK, P, N, C], P encryption.Plaintext, N encryption.Nonce, C encryption.Ciphertext[C]](encryptionKey EK) (*CommitmentKey[EK, P, N, C], error) {
	if utils.IsNil(encryptionKey) {
		return nil, commitments.ErrIsNil.WithMessage("encryption key must not be nil")
	}
	return &CommitmentKey[EK, P, N, C]{encryptionKey: encryptionKey}, nil
}

// CommitmentKey is an IND-CPA commitment key wrapping a public encryption key;
// committing to m computes Enc_ek(m; r). The scheme is binding on the message
// (unique decryption) and computationally hiding (IND-CPA) — the dual of Pedersen's
// perfectly-hiding / computationally-binding tradeoff. It holds no secret; the
// decryption key, held elsewhere, is the trapdoor that breaks hiding (and makes
// the commitment extractable).
type CommitmentKey[EK encryption.EncryptionKey[EK, P, N, C], P encryption.Plaintext, N encryption.Nonce, C encryption.Ciphertext[C]] struct {
	encryptionKey EK
}

type commitmentKeyDTO[EK encryption.EncryptionKey[EK, P, N, C], P encryption.Plaintext, N encryption.Nonce, C encryption.Ciphertext[C]] struct {
	EncryptionKey EK `cbor:"encryption_key"`
}

// Type returns the scheme identifier, derived from the underlying encryption
// scheme's name.
func (k *CommitmentKey[EK, P, N, C]) Type() commitments.Name {
	return commitments.Name(fmt.Sprintf("IND_CPA_COMMITMENT_FROM_%s", k.encryptionKey.Type()))
}

// EncryptionKey returns the public encryption key that parameterises the
// commitment.
func (k *CommitmentKey[EK, P, N, C]) EncryptionKey() EK {
	return k.encryptionKey
}

// SampleWitness draws a fresh encryption nonce from prng via the encryption key.
// Hiding depends on this nonce being fresh and secret, so prng must be a
// cryptographically secure source.
func (k *CommitmentKey[EK, P, N, C]) SampleWitness(prng io.Reader) (*Witness[N], error) {
	nonce, err := k.encryptionKey.SampleNonce(prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not sample nonce from encryption key")
	}
	out, err := NewWitness(nonce)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create witness from nonce")
	}
	return out, nil
}

// CommitWithWitness deterministically computes the commitment Enc_ek(message;
// witness). Encryption is deterministic given the nonce, which is what lets Open
// recompute and compare; a fresh secret nonce is what makes the commitment hiding.
func (k *CommitmentKey[EK, P, N, C]) CommitWithWitness(message *Message[P], witness *Witness[N]) (*Commitment[C], error) {
	if message == nil || witness == nil {
		return nil, commitments.ErrIsNil.WithMessage("message and witness must not be nil")
	}
	ciphertext, err := k.encryptionKey.EncryptWithNonce(message.Value(), witness.Value())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not encrypt message with witness nonce")
	}
	out, err := NewCommitment(ciphertext)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create commitment from ciphertext")
	}
	return out, nil
}

// Open verifies that (message, witness) opens commitment by re-encrypting and
// comparing the ciphertext, returning commitments.ErrVerificationFailed on
// mismatch. Binding ensures a commitment cannot be opened to a second message,
// since that would require one ciphertext to decrypt to two plaintexts.
func (k *CommitmentKey[EK, P, N, C]) Open(commitment *Commitment[C], message *Message[P], witness *Witness[N]) error {
	if err := internal.GenericOpen(k, commitment, message, witness); err != nil {
		return errs.Wrap(err).WithMessage("could not open commitment")
	}
	return nil
}

// Equal reports whether two keys wrap equal encryption keys, treating a nil key as
// equal only to another nil one. Keys are public, so this need not be constant
// time.
func (k *CommitmentKey[EK, P, N, C]) Equal(other *CommitmentKey[EK, P, N, C]) bool {
	if k == nil || other == nil {
		return k == other
	}
	return k.encryptionKey.Equal(other.encryptionKey)
}

// MarshalCBOR encodes the wrapped encryption key.
func (k *CommitmentKey[EK, P, N, C]) MarshalCBOR() ([]byte, error) {
	out, err := serde.MarshalCBOR(&commitmentKeyDTO[EK, P, N, C]{EncryptionKey: k.encryptionKey})
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal commitment key")
	}
	return out, nil
}

// UnmarshalCBOR decodes a commitment key, rejecting a nil encryption key via
// NewCommitmentKey. This is a deserialization trust boundary; validity of the
// encryption key is enforced by its own decoder.
func (k *CommitmentKey[EK, P, N, C]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*commitmentKeyDTO[EK, P, N, C]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to unmarshal commitment key")
	}
	kk, err := NewCommitmentKey(dto.EncryptionKey)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid commitment key in unmarshalled data")
	}
	*k = *kk
	return nil
}
