package redistribute

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw/msp"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/meta/feldman"
)

// BasePublicMaterial contains the public redistribution output shared by all
// holders of the new shard.
type BasePublicMaterial[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	// MSP is the linear access structure describing which sets reconstruct the
	// redistributed secret.
	MSP *msp.MSP[S]
	// VerificationVector authenticates shares distributed under MSP.
	VerificationVector *feldman.VerificationVector[E, S]
}

// BaseShard is a redistributed share bundled with its public verification
// material.
type BaseShard[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	BasePublicMaterial[E, S]

	// Share is the holder's redistributed share of the secret.
	Share *kw.Share[S]
}
