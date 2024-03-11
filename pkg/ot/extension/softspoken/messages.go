package softspoken

import (
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/ot"
)

var _ network.MessageLike = (*Round1Output)(nil)

type Round1Output struct {
	U        ExtMessageBatch   // [κ][η']bits
	Response ChallengeResponse // [σ] + [κ][σ]bits

	_ ds.Incomparable
}

func (r *Round1Output) Validate(L_Xi ...int) error {
	L, Xi := L_Xi[0], L_Xi[1]
	Eta := L * Xi                       // η = L*ξ
	EtaPrimeBytes := Eta/8 + SigmaBytes // η'= η + σ
	for i := range ot.Kappa {
		if len(r.U[i]) != EtaPrimeBytes {
			return errs.NewLength("U[%d] length is %d, should be η'=%d", i, len(r.U[i]), EtaPrimeBytes)
		}
	}
	return nil
}
