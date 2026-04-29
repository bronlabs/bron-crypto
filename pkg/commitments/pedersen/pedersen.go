package pedersen

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
)

// Name identifies the Pedersen commitment scheme.
const Name commitments.Name = "pedersen"

// FiniteAbelianGroup is the algebraic structure required to host Pedersen commitments:
// a finite abelian group with a scalar ring action. Both the prime-order group and
// the unknown-order RSA quotient ZN̂*/{±1} satisfy this interface.
type FiniteAbelianGroup[E FiniteAbelianGroupElement[E, S], S algebra.RingElement[S]] interface {
	algebra.AbelianGroup[E, S]
	algebra.FiniteGroup[E]
}

// FiniteAbelianGroupElement is an element of a FiniteAbelianGroup; it is the
// generator/commitment carrier type used throughout the package.
type FiniteAbelianGroupElement[E FiniteAbelianGroupElement[E, S], S algebra.RingElement[S]] algebra.AbelianGroupElement[E, S]
