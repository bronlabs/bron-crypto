package znstar_test

import "github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"

var (
	_ znstar.UnitGroup[*znstar.RSAGroupElementKnownOrder] = (*znstar.RSAGroupKnownOrder)(nil)
	_ znstar.Unit[*znstar.RSAGroupElementKnownOrder]      = (*znstar.RSAGroupElementKnownOrder)(nil)

	_ znstar.UnitGroup[*znstar.PaillierGroupElementKnownOrder] = (*znstar.PaillierGroupKnownOrder)(nil)
	_ znstar.Unit[*znstar.PaillierGroupElementKnownOrder]      = (*znstar.PaillierGroupElementKnownOrder)(nil)
	_ znstar.UnitGroup[*znstar.RSAGroupElementUnknownOrder]    = (*znstar.RSAGroupUnknownOrder)(nil)
	_ znstar.Unit[*znstar.RSAGroupElementUnknownOrder]         = (*znstar.RSAGroupElementUnknownOrder)(nil)

	_ znstar.UnitGroup[*znstar.PaillierGroupElementUnknownOrder] = (*znstar.PaillierGroupUnknownOrder)(nil)
	_ znstar.Unit[*znstar.PaillierGroupElementUnknownOrder]      = (*znstar.PaillierGroupElementUnknownOrder)(nil)
)
