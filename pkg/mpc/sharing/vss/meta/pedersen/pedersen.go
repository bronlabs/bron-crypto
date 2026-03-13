package pedersen

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/mat"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
)

// Name is the canonical name of this secret sharing scheme.
const Name sharing.Name = "Pedersen Verifiable Secret Sharing Scheme"

type (
	// VerificationVector is the public commitment V = [r_g]G + [r_h]H, a
	// module-valued column vector whose j-th entry is the Pedersen commitment
	// Com(r_g_j, r_h_j) of the j-th components of the secret and blinding
	// random columns. Unlike Feldman's verification vector (which reveals
	// [secret]G in V[0]), the Pedersen verification vector is perfectly hiding:
	// V reveals no information about the secret even to a computationally
	// unbounded adversary.
	VerificationVector[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] = mat.ModuleValuedColumnVector[E, S]
)
