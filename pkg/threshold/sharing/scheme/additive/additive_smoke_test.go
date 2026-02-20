package additive_test

import (
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/scheme/additive"
)

func _[G additive.Group[E], E additive.GroupElement[E]]() {
	var (
		_ sharing.HomomorphicShare[*additive.Share[E], E, *sharing.UnanimityAccessStructure] = (*additive.Share[E])(nil)
	)
}
