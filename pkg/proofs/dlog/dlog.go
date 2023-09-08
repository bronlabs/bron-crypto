package dlog

import (
	"github.com/copperexchange/knox-primitives/pkg/base/curves"
	"github.com/copperexchange/knox-primitives/pkg/base/errs"
)

type Statement = curves.Point

// StatementSubgroupMembershipCheck checks whether the statement is in the prime subgroup, only if the basepoint
// is in the prime subgroup.
func StatementSubgroupMembershipCheck(basePoint curves.Point, statement Statement) error {
	if !basePoint.IsSmallOrder() && statement.IsSmallOrder() {
		return errs.NewVerificationFailed("basepoint is not low order but the statement is")
	}
	return nil
}
