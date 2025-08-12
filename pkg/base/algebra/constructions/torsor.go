package constructions

import "github.com/bronlabs/bron-crypto/pkg/base/algebra"

type Torsor[E algebra.AbelianGroupElement[E, S], S algebra.IntLike[S], XE algebra.Element[XE]] struct {
	g   algebra.AbelianGroup[E, S]
	act algebra.Action[XE, E]
}

type TorsorPoint[E algebra.AbelianGroupElement[E, S], S algebra.IntLike[S], XE algebra.Element[XE]] struct {
	v   algebra.AbelianGroupElement[E, S]
	act algebra.Action[XE, E]
}
