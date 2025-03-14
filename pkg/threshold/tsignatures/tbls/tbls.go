package tbls

import (
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/signatures/bls"
)

type Protocol struct {
	types.ThresholdSignatureProtocol
	Scheme bls.RogueKeyPrevention
}
