package indcpacom

import (
	"fmt"

	"github.com/bronlabs/bron-crypto/pkg/commitments"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
)

type Scheme[
	SK encryption.PrivateKey[SK], PK encryption.PublicKey[PK], M encryption.Plaintext, C encryption.ReRandomisableCiphertext[C, N, PK], N encryption.Nonce,
	KG encryption.KeyGenerator[SK, PK], ENC encryption.Encrypter[PK, M, C, N], DEC encryption.Decrypter[M, C],
] struct {
	encScheme encryption.Scheme[SK, PK, M, C, N, KG, ENC, DEC]
	key       *Key[PK]
}

func (s *Scheme[SK, PK, M, C, N, KG, ENC, DEC]) Name() commitments.Name {
	return commitments.Name(fmt.Sprintf("IND-CPA-Com-%s", s.encScheme.Name()))
}

func (s *Scheme[SK, PK, M, C, N, KG, ENC, DEC]) Committer() *Committer[N, M, C, PK] {
	enc, err := s.encScheme.Encrypter()
	if err != nil {
		panic("failed to create encrypter for IND-CPA commitment scheme: " + err.Error())
	}
	lenc, ok := any(enc).(encryption.LinearlyRandomisedEncrypter[PK, M, C, N])
	if !ok {
		panic("encrypter does not implement LinearlyRandomisedEncrypter required for IND-CPA commitment scheme")
	}
	return &Committer[N, M, C, PK]{enc: lenc, key: s.key}
}

func (s *Scheme[SK, PK, M, C, N, KG, ENC, DEC]) Verifier() *Verifier[N, M, C, PK] {
	return &Verifier[N, M, C, PK]{commitments.NewGenericVerifier(s.Committer())}
}

func (s *Scheme[SK, PK, M, C, N, KG, ENC, DEC]) Key() *Key[PK] {
	return s.key
}
