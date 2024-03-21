package tschnorr

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
)

type PartialSignature struct {
	E curves.Scalar
	R curves.Point
	S curves.Scalar

	_ datastructures.Incomparable
}
