package hash2curve

import "github.com/copperexchange/krypton-primitives/pkg/base/curves"

type CurveMapper interface {
	MapToCurve(u curves.FieldElement) (x, y curves.FieldElement)
}
