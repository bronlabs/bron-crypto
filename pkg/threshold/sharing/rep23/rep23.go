package rep23

import "github.com/bronlabs/bron-crypto/pkg/base/types"

func nextSharingId(id types.SharingID) types.SharingID {
	return id%3 + 1
}

func prevSharingId(id types.SharingID) types.SharingID {
	return (id+1)%3 + 1
}
