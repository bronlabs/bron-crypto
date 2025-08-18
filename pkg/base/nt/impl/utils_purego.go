//go:build purego || nobignum

package impl

import (
	"github.com/bronlabs/bron-crypto/pkg/base/nt/internal"
)

func LCM[N internal.NatMutablePtr[N, NT], NT any](out, a, b N) {
	panic("implement me")
}

func GCDAtLeastOneOdd[N internal.NatMutablePtr[N, NT], NT any](out, a, b N) {
	GCD(out, a, b)
}

func GCD[N internal.NatMutablePtr[N, NT], NT any](out, a, b N) {
	panic("implement me")
}
