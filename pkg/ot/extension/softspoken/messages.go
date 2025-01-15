package softspoken

import (
	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	"github.com/bronlabs/krypton-primitives/pkg/network"
	"github.com/bronlabs/krypton-primitives/pkg/ot"
)

var _ network.Message[types.Protocol] = (*Round1Output)(nil)

type Round1Output struct {
	U        ExtMessageBatch   // [κ][η']bits
	Response ChallengeResponse // [σ] + [κ][σ]bits

	_ ds.Incomparable
}

func (r *Round1Output) Validate(protocol types.Protocol) error {
	otProtocol, ok := protocol.(*ot.Protocol)
	if !ok {
		return errs.NewArgument("protocol is not ot.Protocol")
	}
	L, Xi := otProtocol.L, otProtocol.Xi
	Eta := L * Xi                       // η = L*ξ
	EtaPrimeBytes := Eta/8 + SigmaBytes // η'= η + σ
	for i := range ot.Kappa {
		if len(r.U[i]) != EtaPrimeBytes {
			return errs.NewLength("U[%d] length is %d, should be η'=%d", i, len(r.U[i]), EtaPrimeBytes)
		}
	}
	return nil
}
