package indcpacom

import (
	"fmt"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	"github.com/bronlabs/bron-crypto/pkg/commitments/internal"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
	"github.com/bronlabs/errs-go/errs"
)

func NewCommitmentKey[EK encryption.EncryptionKey[EK, P, N, C], P encryption.Plaintext, N encryption.Nonce, C encryption.Ciphertext[C]](encryptionKey EK) (*CommitmentKey[EK, P, N, C], error) {
	if utils.IsNil(encryptionKey) {
		return nil, commitments.ErrIsNil.WithMessage("encryption key must not be nil")
	}
	return &CommitmentKey[EK, P, N, C]{encryptionKey: encryptionKey}, nil
}

type CommitmentKey[EK encryption.EncryptionKey[EK, P, N, C], P encryption.Plaintext, N encryption.Nonce, C encryption.Ciphertext[C]] struct {
	encryptionKey EK
}

type commitmentKeyDTO[EK encryption.EncryptionKey[EK, P, N, C], P encryption.Plaintext, N encryption.Nonce, C encryption.Ciphertext[C]] struct {
	EncryptionKey EK `cbor:"encryption_key"`
}

func (k *CommitmentKey[EK, P, N, C]) Type() commitments.Name {
	return commitments.Name(fmt.Sprintf("IND_CPA_COMMITMENT_FROM_%s", k.encryptionKey.Type()))
}

func (k *CommitmentKey[EK, P, N, C]) EncryptionKey() EK {
	return k.encryptionKey
}

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

func (k *CommitmentKey[EK, P, N, C]) Open(commitment *Commitment[C], message *Message[P], witness *Witness[N]) error {
	if err := internal.GenericOpen(k, commitment, message, witness); err != nil {
		return errs.Wrap(err).WithMessage("could not open commitment")
	}
	return nil
}

func (k *CommitmentKey[EK, P, N, C]) Equal(other *CommitmentKey[EK, P, N, C]) bool {
	if k == nil || other == nil {
		return k == other
	}
	return k.encryptionKey.Equal(other.encryptionKey)
}

func (k *CommitmentKey[EK, P, N, C]) MarshalCBOR() ([]byte, error) {
	out, err := serde.MarshalCBOR(&commitmentKeyDTO[EK, P, N, C]{EncryptionKey: k.encryptionKey})
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal commitment key")
	}
	return out, nil
}

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
