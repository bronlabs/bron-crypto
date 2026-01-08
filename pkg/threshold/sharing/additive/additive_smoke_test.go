package additive_test

import (
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/additive"
)

func _[G additive.Group[E], E additive.GroupElement[E]]() {
	var (
		_ sharing.AdditiveShare[*additive.Share[E], E, *sharing.MinimalQualifiedAccessStructure] = (*additive.Share[E])(nil)
		_ sharing.AdditivelyShareableSecret[*additive.Secret[E], E]                              = (*additive.Secret[E])(nil)

		_ sharing.AdditiveSSS[*additive.Share[E], E, *additive.Secret[E], E, *additive.DealerOutput[E], *sharing.MinimalQualifiedAccessStructure] = (*additive.Scheme[E])(nil)
	)
}
