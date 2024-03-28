package softspoken

import (
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/ot"
)

var _ network.Message[ot.Protocol] = (*Round1Output)(nil)

type Round1Output struct {
	U        ExtMessageBatch   // [κ][η']bits
	Response ChallengeResponse // [σ] + [κ][σ]bits

	_ ds.Incomparable
}

func (r *Round1Output) Validate(protocol ot.Protocol) error {
	Eta := protocol.L() * protocol.Xi() // η = L*ξ
	EtaPrimeBytes := Eta/8 + SigmaBytes // η'= η + σ
	for i := range ot.Kappa {
		if len(r.U[i]) != EtaPrimeBytes {
			return errs.NewLength("U[%d] length is %d, should be η'=%d", i, len(r.U[i]), EtaPrimeBytes)
		}
	}
	return nil
}
