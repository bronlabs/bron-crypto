package prss

import "github.com/copperexchange/krypton-primitives/pkg/base/curves"

type Seed struct {
	Ra map[int]curves.Scalar
}
