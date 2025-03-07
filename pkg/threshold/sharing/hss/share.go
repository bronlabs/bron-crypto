package hss

import "github.com/bronlabs/krypton-primitives/pkg/base/curves"

type HierarchicalShare struct {
	I     uint
	J     uint
	Value curves.Scalar
}
