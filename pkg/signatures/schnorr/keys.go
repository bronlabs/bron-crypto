package schnorr

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
)

type PublicKey struct {
	A curves.Point

	_ ds.Incomparable
}

type PrivateKey struct {
	S curves.Scalar
	PublicKey

	_ ds.Incomparable
}
