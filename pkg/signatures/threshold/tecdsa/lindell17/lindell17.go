package lindell17

import (
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/paillier"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold"
)

const (
	// Threshold Lindell 2017 threshold (always 2).
	Threshold = 2
)

type Participant interface {
	integration.Participant

	IsSignatureAggregator() bool
}

type Shard struct {
	SigningKeyShare         *threshold.SigningKeyShare
	PaillierSecretKey       *paillier.SecretKey
	PaillierPublicKeys      map[integration.IdentityHash]*paillier.PublicKey
	PaillierEncryptedShares map[integration.IdentityHash]paillier.CipherText
}

type PartialSignature struct {
	C3 paillier.CipherText
}

type PreSignature struct {
	K    curves.Scalar
	BigR map[integration.IdentityHash]curves.Point
}

type PreSignatureBatch struct {
	PreSignatures []*PreSignature
}
