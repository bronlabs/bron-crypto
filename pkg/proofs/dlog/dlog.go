package dlog

import (
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/edwards25519"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
)

type Statement = curves.Point

// StatementSubgroupMembershipCheck checks whether the statement is in the prime subgroup, only if the basepoint
// is in the prime subgroup.
func StatementSubgroupMembershipCheck(basePoint curves.Point, statement Statement) error {
	curve := basePoint.Curve()
	if curve.Name() == edwards25519.Name {
		edBasePoint, ok := basePoint.(*edwards25519.PointEd25519)
		if !ok {
			return errs.NewInvalidType("basepoint is not an edwards point. this should not happen.")
		}
		edStatement, ok := statement.(*edwards25519.PointEd25519)
		if !ok {
			return errs.NewInvalidCurve("the statement doesn't belong to edwards25519 but the basepoint does")
		}
		if !edBasePoint.IsSmallOrder() && edStatement.IsSmallOrder() {
			return errs.NewVerificationFailed("basepoint is not low order but the statement is")
		}
	}
	return nil
}
