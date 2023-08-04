package lindell22

import (
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
)

type Participant interface {
	integration.Participant

	IsSignatureAggregator() bool
}

type PartialSignature struct {
	R curves.Point
	S curves.Scalar
}
