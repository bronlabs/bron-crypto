package curves2

import (
	"github.com/cronokirby/saferith"
	"io"
)

type Group interface {
	FromRandom(prng io.Reader) Group
	Clone() Group
	Identity() Group
	Generator() Group
	Operate(rhs Group) Group
	Inv() Group
	Exp(nat saferith.Nat) Group
	IsIdentity() Group
	Equals(rhs Group)
	Order() saferith.Nat
}
