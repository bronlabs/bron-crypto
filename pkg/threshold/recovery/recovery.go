package recovery

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/feldman"
)

type Output[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	share        *feldman.Share[S]
	verification feldman.VerificationVector[G, S]
}

func (out *Output[G, S]) Share() *feldman.Share[S] {
	return out.share
}

func (out *Output[G, S]) Verification() feldman.VerificationVector[G, S] {
	return out.verification
}
