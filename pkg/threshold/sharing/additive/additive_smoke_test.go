package additive_test

import (
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/additive"
)

func _[G additive.Group[E], E additive.GroupElement[E]]() {
	var (
		_ sharing.HomomorphicShare[*additive.Share[E], E, *sharing.MinimalQualifiedAccessStructure] = (*additive.Share[E])(nil)
	)
}
