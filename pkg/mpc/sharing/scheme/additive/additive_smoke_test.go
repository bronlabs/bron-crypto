package additive_test

import (
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/additive"
)

func _[G additive.Group[E], E additive.GroupElement[E]]() {
	var (
		_ sharing.LinearShare[*additive.Share[E], E] = (*additive.Share[E])(nil)
	)
}
