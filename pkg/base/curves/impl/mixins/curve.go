package mixins

import (
	"github.com/cronokirby/saferith"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
)

type Curve struct {
	groupoid       impl.Groupoid[curves.Curve, curves.Point]
	cyclicGroupoid impl.CyclicGroupoid[curves.Curve, curves.Point]
}

func (c *Curve) Cardinality() *saferith.Nat {
	return c.groupoid.Cardinality()
}

func (c *Curve) BasePoint() curves.Point {
	return c.cyclicGroupoid.BasePoint()
}
