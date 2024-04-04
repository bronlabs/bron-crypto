package tbls

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/bls"
)

type Protocol struct {
	types.ThresholdSignatureProtocol
	Scheme bls.RogueKeyPrevention
}
