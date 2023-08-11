package lindell22

import (
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold"
)

type Participant interface {
	integration.Participant

	IsSignatureAggregator() bool
}

type PartialSignature struct {
	R curves.Point
	S curves.Scalar
}

type Shard struct {
	SigningKeyShare *threshold.SigningKeyShare
	PublicKeyShares *threshold.PublicKeyShares
}

type PreSignature struct {
	K    curves.Scalar
	BigR map[integration.IdentityKey]curves.Point
}

type PreSignatureBatch struct {
	PreSignatures []*PreSignature
}
