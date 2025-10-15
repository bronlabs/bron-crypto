package znstar

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/modular"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar/internal"
)

type (
	UnitGroup[U unitCrtp[U]]                                          = internal.UnitGroup[U]
	KnowledgeOfOrder[A modular.Arithmetic, G UnitGroup[U], U Unit[U]] = internal.KnowledgeOfOrder[A, G, U]
	unitCrtp[U interface {
		algebra.MultiplicativeGroupElement[U]
		algebra.MultiplicativeSemiModuleElement[U, *num.Nat]
	}] = internal.UnitCrtp[U]

	Unit[U unitCrtp[U]] = internal.Unit[U]
)
