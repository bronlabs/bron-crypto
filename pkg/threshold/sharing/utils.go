package sharing

import (
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
)

func NewOrdinalShareholderSet(count uint) ds.Set[ID] {
	out := hashset.NewComparable[ID]()
	for i := range count {
		out.Add(ID(i))
	}
	return out.Freeze()
}

type MinimalQualifiedAccessStructure struct {
	ps ds.Set[ID]
}

func (a *MinimalQualifiedAccessStructure) Shareholders() ds.Set[ID] {
	return a.ps
}
func (a *MinimalQualifiedAccessStructure) IsAuthorized(ids ...ID) bool {
	return a.ps.Size() == len(ids) && a.ps.Equal(hashset.NewComparable(ids...).Freeze())
}

func NewMinimalQualifiedAccessStructure(shareholders ds.Set[ID]) (*MinimalQualifiedAccessStructure, error) {
	if shareholders == nil {
		return nil, errs.NewIsNil("ids cannot be nil")
	}
	if shareholders.Size() < 2 {
		return nil, errs.NewValue("ids must have at least 2 shareholders")
	}
	return &MinimalQualifiedAccessStructure{
		ps: shareholders,
	}, nil
}

func CollectIDs[S Share[S]](shares ...S) ([]ID, error) {
	return sliceutils.MapErrFunc(shares, func(s S) (ID, error) {
		if utils.IsNil(s) {
			return 0, errs.NewIsNil("share cannot be nil")
		}
		return s.ID(), nil
	})
}
