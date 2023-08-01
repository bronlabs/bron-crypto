package mult

import (
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/ot/extension/softspoken"
)

// These should really be parameters, but we are declaring them as constants for readability of struct field types.
const (
	// Batch size of multiplication functionality itself. It should be less < loglog q. In DKLs23, L=2 for Alice and effectively L=1 for Bob.
	L = 2
	// commputational security parameter
	Kappa      = softspoken.Kappa
	KappaBytes = Kappa >> 3

	// statistical security parameter
	S      = softspoken.Sigma
	SBytes = S >> 3

	// number of random choice bits per element in each batch
	Xi      = Kappa + 2*S
	XiBytes = Xi / 8

	// OTe batch size
	Eta      = Xi * L
	EtaBytes = Eta / 8
)

type OutputShares = [L]curves.Scalar
