//go:build boringnat && !purego && !nobignum

package nat

import "github.com/copperexchange/krypton-primitives/pkg/base/nat/internal/bignum"

var BigNats Nats = &bignum.BnNats{}
