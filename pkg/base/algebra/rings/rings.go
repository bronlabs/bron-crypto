package rings

import "github.com/bronlabs/bron-crypto/pkg/base/algebra"

type (
	Ring[RE algebra.RingElement[RE]]        algebra.Ring[RE]
	RingElement[RE algebra.RingElement[RE]] algebra.RingElement[RE]
)

func GetRing[E RingElement[E]](e E) Ring[E] {
	r, ok := e.Structure().(Ring[E])
	if !ok {
		panic("RingElement does not have a Ring structure")
	}
	return r
}
