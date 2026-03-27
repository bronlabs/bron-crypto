package redistribute

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw/msp"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/meta/feldman"
)

type BasePublicMaterial[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	MSP                *msp.MSP[S]
	VerificationVector *feldman.VerificationVector[E, S]
}

type BaseShard[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	BasePublicMaterial[E, S]

	Share *kw.Share[S]
}
