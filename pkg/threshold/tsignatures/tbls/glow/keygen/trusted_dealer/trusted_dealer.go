package trusted_dealer

import (
	"github.com/bronlabs/bron-crypto/pkg/base/curves/bls12381"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tbls/boldyreva02/keygen/trusted_dealer"
)

var Keygen = trusted_dealer.Keygen[bls12381.G1]
