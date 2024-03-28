package types

import (
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
)

type SharingID uint
type SharingConfig AbstractIdentitySpace[SharingID]

func DeriveSharingConfig(identityKeys ds.Set[IdentityKey]) SharingConfig {
	return NewAbstractIdentitySpace[SharingID](identityKeys)
}
