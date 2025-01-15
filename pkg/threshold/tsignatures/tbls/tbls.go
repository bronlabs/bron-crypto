package tbls

import (
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	"github.com/bronlabs/krypton-primitives/pkg/signatures/bls"
)

type Protocol struct {
	types.ThresholdSignatureProtocol
	Scheme bls.RogueKeyPrevention
}
