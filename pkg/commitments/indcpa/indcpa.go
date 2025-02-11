package indcpa_comm

import (
	"io"

	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/commitments"
	"github.com/bronlabs/krypton-primitives/pkg/indcpa"
)

type Commitment[C indcpa.CipherText] struct {
	CipherText C
}

type CommittingKey[PK indcpa.EncryptionKey[P, R, C], P indcpa.PlainText, R indcpa.Nonce, C indcpa.CipherText] struct {
	PublicKey PK
}

func NewCommittingKey[PK indcpa.EncryptionKey[P, R, C], P indcpa.PlainText, R indcpa.Nonce, C indcpa.CipherText](publicKey PK) commitments.CommittingKey[*Commitment[C], P, R] {
	return &CommittingKey[PK, P, R, C]{
		PublicKey: publicKey,
	}
}

func (ck *CommittingKey[PK, P, R, C]) RandomWitness(prng io.Reader) (witness R, err error) {
	r, err := ck.PublicKey.RandomNonce(prng)
	if err != nil {
		return *new(R), errs.WrapRandomSample(err, "cannot sample witness")
	}

	return r, nil
}

func (ck *CommittingKey[PK, P, R, C]) CommitWithWitness(message P, witness R) (commitment *Commitment[C], err error) {
	c, err := ck.PublicKey.EncryptWithNonce(message, witness)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot commit to message")
	}

	return &Commitment[C]{
		CipherText: c,
	}, nil
}

func (ck *CommittingKey[PK, P, R, C]) Commit(message P, prng io.Reader) (commitment *Commitment[C], witness R, err error) {
	r, err := ck.RandomWitness(prng)
	if err != nil {
		return nil, *new(R), errs.WrapRandomSample(err, "cannot sample witness")
	}

	c, err := ck.CommitWithWitness(message, r)
	if err != nil {
		return nil, *new(R), errs.WrapRandomSample(err, "cannot commit to message")
	}

	return c, r, nil
}

func (ck *CommittingKey[PK, P, R, C]) Verify(commitment *Commitment[C], message P, witness R) (err error) {
	c, err := ck.CommitWithWitness(message, witness)
	if err != nil {
		return errs.WrapVerification(err, "verification failed")
	}

	if ok := ck.PublicKey.CipherTextEqual(c.CipherText, commitment.CipherText); !ok {
		return errs.NewVerification("verification failed")
	}

	return nil
}
