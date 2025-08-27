package softspoken

import (
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

type Round1P2P struct {
	u [Kappa][]byte // [κ][η']bits
	//Response ChallengeResponse // [σ] + [κ][σ]bits
}

func (r1 *Round1P2P) Validate(xi, l int) error {
	eta := l * xi                       // η = L*ξ
	etaPrimeBytes := eta/8 + SigmaBytes // η'= η + σ
	for i := range Kappa {
		if len(r1.u[i]) != etaPrimeBytes {
			return errs.NewLength("U[%d] length is %d, should be η'=%d", i, len(r1.u[i]), etaPrimeBytes)
		}
	}
	return nil
}
