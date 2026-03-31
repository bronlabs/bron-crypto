package boolexpr_test

import (
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/boolexpr"
)

var _ accessstructures.Monotone = (*boolexpr.ThresholdGateAccessStructure)(nil)
