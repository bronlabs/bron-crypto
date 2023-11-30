package curves2

import (
	"github.com/cronokirby/saferith"
	"io"
)

type GroupElement interface {
	FromRandom(prng io.Reader) GroupElement
	Clone() GroupElement
	Identity() GroupElement
	Generator() GroupElement
	Double() GroupElement
	Triple() GroupElement
	Operate(rhs GroupElement) GroupElement
	Inv() GroupElement
	Exp(nat saferith.Nat) GroupElement
	IsIdentity() GroupElement
	Equals(rhs GroupElement)
	Order() saferith.Nat
}
