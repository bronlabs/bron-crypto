package additive_test

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/scheme/additive"
)

func _[G additive.Group[E], E additive.GroupElement[E]]() {
	var (
		_ sharing.LinearShare[*additive.Share[E], E, algebra.Numeric] = (*additive.Share[E])(nil)
	)
}
