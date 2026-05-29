package indcpacom_test

import (
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	"github.com/bronlabs/bron-crypto/pkg/commitments/indcpacom"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
)

func _[
	EK encryption.HomomorphicEncryptionKey[EK, P, N, C, S],
	P encryption.Plaintext,
	N encryption.Nonce,
	C encryption.Ciphertext[C],
	S any,
]() {
	var (
		_ commitments.CommitmentKey[*indcpacom.CommitmentKey[EK, P, N, C], *indcpacom.Message[P], *indcpacom.Witness[N], *indcpacom.Commitment[C]] = (*indcpacom.CommitmentKey[EK, P, N, C])(nil)

		_ commitments.HomomorphicCommitmentKey[*indcpacom.HomomorphicCommitmentKey[EK, P, N, C, S], *indcpacom.Message[P], *indcpacom.Witness[N], *indcpacom.Commitment[C], S] = (*indcpacom.HomomorphicCommitmentKey[EK, P, N, C, S])(nil)
	)
}
