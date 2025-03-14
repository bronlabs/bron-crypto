package tschnorr

import (
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures"
)

type PartialSignature struct {
	E curves.Scalar
	R curves.Point
	S curves.Scalar

	_ datastructures.Incomparable
}
