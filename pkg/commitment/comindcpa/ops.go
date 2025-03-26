package comindcpa

import (
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/commitment"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
)

type committer[N encryption.Nonce, PK encryption.PublicKey[PK], P encryption.Plaintext, C interface {
	encryption.Ciphertext
	types.Transparent[CT]
}, CT ds.Equatable[CT]] struct {
	encrypter encryption.Encrypter[PK, P, C, N]
	pk        PK
}

func (s *committer[N, PK, P, C, CT]) Scheme() types.Scheme[commitment.Type] {
	return nil
}

func (s *committer[N, PK, P, C, CT]) Commit(message *Message[P], prng types.PRNG) (*Commitment[C, CT], *Witness[N], error) {
	ciphertext, nonce, err := s.encrypter.Encrypt(message.v, s.pk, prng, nil)
	if err != nil {
		return nil, nil, err
	}
	return &Commitment[C, CT]{v: ciphertext}, &Witness[N]{v: nonce}, nil
}

func (s *committer[N, PK, P, C, CT]) CommitWithWitness(message *Message[P], witness *Witness[N]) (*Commitment[C, CT], error) {
	ciphertext, err := s.encrypter.EncryptWithNonce(message.v, s.pk, witness.v, nil)
	if err != nil {
		return nil, err
	}
	return &Commitment[C, CT]{v: ciphertext}, nil
}

type verifier[N encryption.Nonce, PK encryption.PublicKey[PK], P encryption.Plaintext, C interface {
	encryption.Ciphertext
	types.Transparent[CT]
}, CT ds.Equatable[CT]] struct {
	encrypter encryption.Encrypter[PK, P, C, N]
}

func (v *verifier[N, PK, P, C, CT]) Scheme() types.Scheme[commitment.Type] {
	return nil
}

func (v *verifier[N, PK, P, C, CT]) Verify(commitment *Commitment[C, CT], message *Message[P], opening *Opening[N, PK]) error {
	reconstructedCiphertext, err := v.encrypter.EncryptWithNonce(message.v, opening.pk, opening.w.v, nil)
	if err != nil {
		return errs.WrapFailed(err, "failed to reconstruct ciphertext")
	}
	if !commitment.v.Value().Equal(reconstructedCiphertext.Value()) {
		return errs.NewVerification("commitment does not match ciphertext")
	}
	return nil
}
