package k256

import (
	"sync"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
)

var (
	opInitonce sync.Once
	opInstance curves.PointAddition[curves.Curve, curves.BaseField, curves.Point, curves.BaseFieldElement]
)

func opInit() {
	// opInstance = curves.PointAddition[Curve, BaseField, Point, BaseFieldElement]{}
	return
}

func PointAddition() *curves.PointAddition[curves.Curve, curves.BaseField, curves.Point, curves.BaseFieldElement] {
	// opInitonce.Do(opInit)
	// return &opInstance
	return nil
}
