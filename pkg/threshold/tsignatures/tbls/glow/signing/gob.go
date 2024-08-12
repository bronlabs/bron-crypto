package signing

import "github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"

func init() {
	bls12381.RegisterForGob()
}
