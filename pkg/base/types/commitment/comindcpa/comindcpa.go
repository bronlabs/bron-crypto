package comindcpa

import (
	"fmt"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/base/types/commitment"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
)

type Message[P encryption.Plaintext] struct {
	v P
}
type Witness[W encryption.Nonce] struct {
	v W
}
type Commitment[C interface {
	encryption.Ciphertext
	types.Transparent[CT]
}, CT ds.Equatable[CT]] struct {
	v C
}

type Opening[N encryption.Nonce, PK encryption.PublicKey[PK]] struct {
	w  *Witness[N]
	pk PK
}

func (o *Opening[N, PK]) Witness() *Witness[N] {
	return o.w
}

func (o *Opening[N, PK]) PublicKey() PK {
	return o.pk
}

func NewScheme[N encryption.Nonce, PK encryption.PublicKey[PK], P encryption.Plaintext, C interface {
	encryption.Ciphertext
	types.Transparent[CT]
}, CT ds.Equatable[CT]](indcpaEncrypter encryption.Encrypter[PK, P, C, N], pk PK) commitment.Scheme[*Witness[N], *Opening[N, PK], *Message[P], *Commitment[C, CT]] {
	return &scheme[N, PK, P, C, CT]{indcpaEncrypter, pk}
}

type scheme[N encryption.Nonce, PK encryption.PublicKey[PK], P encryption.Plaintext, C interface {
	encryption.Ciphertext
	types.Transparent[CT]
}, CT ds.Equatable[CT]] struct {
	encrypter encryption.Encrypter[PK, P, C, N]
	pk        PK
}

func (s *scheme[N, PK, P, C, CT]) Type() commitment.Type {
	return commitment.Type(fmt.Sprintf("commitment scheme induced from IND-CPA encryption scheme %s", s.encrypter.Scheme().Type()))
}

func (s *scheme[N, PK, P, C, CT]) Committer() commitment.Committer[*Witness[N], *Message[P], *Commitment[C, CT]] {
	return &committer[N, PK, P, C, CT]{s.encrypter, s.pk}
}

func (s *scheme[N, PK, P, C, CT]) Verifier() commitment.Verifier[*Witness[N], *Opening[N, PK], *Message[P], *Commitment[C, CT]] {
	return &verifier[N, PK, P, C, CT]{s.encrypter}
}
