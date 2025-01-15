package signing

import "github.com/bronlabs/krypton-primitives/pkg/base/curves/bls12381"

//nolint:gochecknoinits // We need the init function here.
func init() {
	bls12381.RegisterForGob()
}
