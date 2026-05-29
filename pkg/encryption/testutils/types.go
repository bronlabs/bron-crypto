package testutils

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
)

type (
	TypeErasedEncryptionKey[P encryption.Plaintext, N encryption.Nonce, C encryption.Ciphertext[C]] interface {
		encryption.NonceSampler[N]
		EncryptWithNonce(P, N) (C, error)
	}
	TypeErasedHomomorphicEncryptionKey[P encryption.Plaintext, N encryption.Nonce, C encryption.Ciphertext[C], S any] interface {
		TypeErasedEncryptionKey[P, N, C]
		encryption.Homomorphic[P, N, C, S]
	}
	TypeErasedGroupHomomorphicEncryptionKey[
		P interface {
			encryption.Plaintext
			base.Transparent[PV]
		}, PG algebra.FiniteGroup[PV], PV algebra.GroupElement[PV],
		N interface {
			encryption.Nonce
			base.Transparent[NV]
		}, NG algebra.FiniteGroup[NV],
		NV algebra.GroupElement[NV],
		C interface {
			encryption.Ciphertext[C]
			base.Transparent[CV]
		}, CG algebra.FiniteGroup[CV], CV algebra.GroupElement[CV],
		S any,
	] interface {
		TypeErasedHomomorphicEncryptionKey[P, N, C, S]
		encryption.GroupHomomorphic[P, PG, PV, N, NG, NV, C, CG, CV, S]
	}
)
