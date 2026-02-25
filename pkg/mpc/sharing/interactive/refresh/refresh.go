package refresh

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/feldman"
)

type Output[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	share              *feldman.Share[S]
	verificationVector feldman.VerificationVector[G, S]
}

func (o *Output[G, S]) Share() *feldman.Share[S] {
	return o.share
}

func (o *Output[G, S]) VerificationVector() feldman.VerificationVector[G, S] {
	return o.verificationVector
}
