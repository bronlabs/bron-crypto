package indcpacom

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
)

type Committer[
	N encryption.Nonce, P encryption.Plaintext, CX encryption.ReRandomisableCiphertext[CX, N, PK],
	PK encryption.PublicKey[PK],
] struct {
	key *Key[PK]
	enc encryption.LinearlyRandomisedEncrypter[PK, P, CX, N]
}

func (c *Committer[N, P, CX, PK]) Commit(
	message *Message[P],
	prng io.Reader,
) (*Commitment[CX, N, PK], *Witness[N], error) {
	if message == nil || prng == nil {
		return nil, nil, ErrIsNil.WithStackFrame()
	}
	ciphertext, nonce, err := c.enc.Encrypt(message.Value(), c.key.Value(), prng)
	if err != nil {
		return nil, nil, errs2.Wrap(err).WithMessage("cannot encrypt message for commitment")
	}
	return &Commitment[CX, N, PK]{v: ciphertext}, &Witness[N]{v: nonce}, nil
}

func (c *Committer[N, P, CX, PK]) CommitWithWitness(
	message *Message[P],
	witness *Witness[N],
) (*Commitment[CX, N, PK], error) {
	if message == nil || witness == nil {
		return nil, ErrIsNil.WithStackFrame()
	}
	ciphertext, err := c.enc.EncryptWithNonce(message.Value(), c.key.Value(), witness.Value())
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot encrypt message for commitment with witness")
	}
	return &Commitment[CX, N, PK]{v: ciphertext}, nil
}

type Verifier[
	N encryption.Nonce, P encryption.Plaintext, CX encryption.ReRandomisableCiphertext[CX, N, PK],
	PK encryption.PublicKey[PK],
] struct {
	c *commitments.GenericVerifier[
		*Committer[N, P, CX, PK],
		*Witness[N],
		*Message[P],
		*Commitment[CX, N, PK],
	]
}
