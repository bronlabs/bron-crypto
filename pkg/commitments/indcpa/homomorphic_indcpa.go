package indcpa_comm

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/indcpa"
)

type HomomorphicCommittingKey[PK indcpa.HomomorphicEncryptionKey[P, R, C, S], P indcpa.PlainText, R indcpa.Nonce, C indcpa.CipherText, S indcpa.Scalar] struct {
	CommittingKey[PK, P, R, C]
}

type HomomorphicCommitment[C indcpa.CipherText] struct {
	Commitment[C]
}

func NewHomomorphicCommittingKey[PK indcpa.HomomorphicEncryptionKey[P, R, C, S], P indcpa.PlainText, R indcpa.Nonce, C indcpa.CipherText, S indcpa.Scalar](publicKey PK) *HomomorphicCommittingKey[PK, P, R, C, S] {
	return &HomomorphicCommittingKey[PK, P, R, C, S]{
		CommittingKey: CommittingKey[PK, P, R, C]{
			PublicKey: publicKey,
		},
	}
}

func (ck *HomomorphicCommittingKey[PK, P, R, C, S]) RandomWitness(prng io.Reader) (witness R, err error) {
	r, err := ck.PublicKey.RandomNonce(prng)
	if err != nil {
		return *new(R), errs.WrapRandomSample(err, "cannot sample witness")
	}

	return r, nil
}

func (ck *HomomorphicCommittingKey[PK, P, R, C, S]) CommitWithWitness(message P, witness R) (commitment *HomomorphicCommitment[C], err error) {
	c, err := ck.PublicKey.EncryptWithNonce(message, witness)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot commit to message")
	}

	return &HomomorphicCommitment[C]{
		Commitment: Commitment[C]{CipherText: c},
	}, nil
}

func (ck *HomomorphicCommittingKey[PK, P, R, C, S]) Commit(message P, prng io.Reader) (commitment *HomomorphicCommitment[C], witness R, err error) {
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

func (ck *HomomorphicCommittingKey[PK, P, R, C, S]) Verify(commitment *HomomorphicCommitment[C], message P, witness R) (err error) {
	c, err := ck.CommitWithWitness(message, witness)
	if err != nil {
		return errs.WrapVerification(err, "verification failed")
	}

	if ok := ck.PublicKey.CipherTextEqual(c.CipherText, commitment.CipherText); !ok {
		return errs.NewVerification("verification failed")
	}

	return nil
}

func (ck *HomomorphicCommittingKey[PK, P, R, C, S]) MessageAdd(lhs, rhs P) (message P, err error) {
	m, err := ck.PublicKey.PlainTextAdd(lhs, rhs)
	if err != nil {
		return *new(P), errs.WrapFailed(err, "cannot add message")
	}

	return m, nil
}

func (ck *HomomorphicCommittingKey[PK, P, R, C, S]) MessageSub(lhs, rhs P) (message P, err error) {
	m, err := ck.PublicKey.PlainTextSub(lhs, rhs)
	if err != nil {
		return *new(P), errs.WrapFailed(err, "cannot sub message")
	}

	return m, nil
}

func (ck *HomomorphicCommittingKey[PK, P, R, C, S]) MessageNeg(x P) (message P, err error) {
	m, err := ck.PublicKey.PlainTextNeg(x)
	if err != nil {
		return *new(P), errs.WrapFailed(err, "cannot neg message")
	}

	return m, nil
}

func (ck *HomomorphicCommittingKey[PK, P, R, C, S]) MessageMul(lhs P, rhs S) (message P, err error) {
	m, err := ck.PublicKey.PlainTextMul(lhs, rhs)
	if err != nil {
		return *new(P), errs.WrapFailed(err, "cannot mul message")
	}

	return m, nil
}

func (ck *HomomorphicCommittingKey[PK, P, R, C, S]) CommitmentAdd(lhs, rhs *HomomorphicCommitment[C]) (commitment *HomomorphicCommitment[C], err error) {
	c, err := ck.PublicKey.CipherTextAdd(lhs.CipherText, rhs.CipherText)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot add commitments")
	}

	return &HomomorphicCommitment[C]{
		Commitment: Commitment[C]{CipherText: c},
	}, nil
}

func (ck *HomomorphicCommittingKey[PK, P, R, C, S]) CommitmentAddMessage(lhs *HomomorphicCommitment[C], rhs P) (commitment *HomomorphicCommitment[C], err error) {
	c, err := ck.PublicKey.CipherTextAddPlainText(lhs.CipherText, rhs)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot add commitments")
	}

	return &HomomorphicCommitment[C]{
		Commitment: Commitment[C]{CipherText: c},
	}, nil
}

func (ck *HomomorphicCommittingKey[PK, P, R, C, S]) CommitmentSub(lhs, rhs *HomomorphicCommitment[C]) (commitment *HomomorphicCommitment[C], err error) {
	c, err := ck.PublicKey.CipherTextSub(lhs.CipherText, rhs.CipherText)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot add commitments")
	}

	return &HomomorphicCommitment[C]{
		Commitment: Commitment[C]{CipherText: c},
	}, nil
}

func (ck *HomomorphicCommittingKey[PK, P, R, C, S]) CommitmentSubMessage(lhs *HomomorphicCommitment[C], rhs P) (commitment *HomomorphicCommitment[C], err error) {
	c, err := ck.PublicKey.CipherTextSubPlainText(lhs.CipherText, rhs)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot add commitments")
	}

	return &HomomorphicCommitment[C]{
		Commitment: Commitment[C]{CipherText: c},
	}, nil
}

func (ck *HomomorphicCommittingKey[PK, P, R, C, S]) CommitmentNeg(x *HomomorphicCommitment[C]) (commitment *HomomorphicCommitment[C], err error) {
	c, err := ck.PublicKey.CipherTextNeg(x.CipherText)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot neg commitments")
	}

	return &HomomorphicCommitment[C]{
		Commitment: Commitment[C]{CipherText: c},
	}, nil
}

func (ck *HomomorphicCommittingKey[PK, P, R, C, S]) CommitmentMul(lhs *HomomorphicCommitment[C], rhs S) (commitment *HomomorphicCommitment[C], err error) {
	c, err := ck.PublicKey.CipherTextMul(lhs.CipherText, rhs)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot neg commitments")
	}

	return &HomomorphicCommitment[C]{
		Commitment: Commitment[C]{CipherText: c},
	}, nil
}

func (ck *HomomorphicCommittingKey[PK, P, R, C, S]) WitnessAdd(lhs, rhs R) (witness R, err error) {
	r, err := ck.PublicKey.NonceAdd(lhs, rhs)
	if err != nil {
		return *new(R), errs.WrapFailed(err, "cannot add witnesses")
	}

	return r, nil
}

func (ck *HomomorphicCommittingKey[PK, P, R, C, S]) WitnessSub(lhs, rhs R) (witness R, err error) {
	r, err := ck.PublicKey.NonceSub(lhs, rhs)
	if err != nil {
		return *new(R), errs.WrapFailed(err, "cannot add witnesses")
	}

	return r, nil
}

func (ck *HomomorphicCommittingKey[PK, P, R, C, S]) WitnessNeg(x R) (witness R, err error) {
	r, err := ck.PublicKey.NonceNeg(x)
	if err != nil {
		return *new(R), errs.WrapFailed(err, "cannot neg witnesses")
	}

	return r, nil
}

func (ck *HomomorphicCommittingKey[PK, P, R, C, S]) WitnessMul(lhs R, rhs S) (witness R, err error) {
	r, err := ck.PublicKey.NonceMul(lhs, rhs)
	if err != nil {
		return *new(R), errs.WrapFailed(err, "cannot neg witnesses")
	}

	return r, nil
}
