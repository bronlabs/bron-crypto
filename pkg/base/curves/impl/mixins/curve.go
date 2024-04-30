package mixins

import (
	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
)

type Curve struct {
	groupoid       impl.Groupoid[curves.Curve, curves.Point]
	cyclicGroupoid impl.CyclicGroupoid[curves.Curve, curves.Point]
}

func (c *Curve) Cardinality() *saferith.Modulus {
	return c.groupoid.Cardinality()
}

func (c *Curve) BasePoint() curves.Point {
	return c.cyclicGroupoid.BasePoint()
}
