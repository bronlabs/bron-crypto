package bigint

import (
	"fmt"

	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer/impl/mixins"
)

var znxName = fmt.Sprintf("%s_ZnX", Name)

var (
	_ integer.ZnX[*ZnX, *IntX]     = (*ZnX)(nil)
	_ mixins.HolesZnX[*ZnX, *IntX] = (*ZnX)(nil)
)

type ZnX struct {
	mixins.ZnX[*ZnX, *IntX]
}

type IntX struct {
	mixins.IntX[*ZnX, *IntX]
	V *NatPlus
}
