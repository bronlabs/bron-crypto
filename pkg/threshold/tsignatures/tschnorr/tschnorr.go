package tschnorr

import (
	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	"github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
)

type PartialSignature struct {
	E curves.Scalar
	R curves.Point
	S curves.Scalar

	_ datastructures.Incomparable
}
