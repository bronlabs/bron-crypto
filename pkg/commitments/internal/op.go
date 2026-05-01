package internal

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	"github.com/bronlabs/errs-go/errs"
)

func Op[
	T base.Transparent[TV], TV algebra.GroupElement[TV],
](
	newFunc func(TV) (T, error),
	first, second T,
	rest ...T,
) (T, error) {
	if utils.IsNil(first) || utils.IsNil(second) {
		return *new(T), commitments.ErrIsNil.WithMessage("first and second objects must not be nil")
	}
	restValues, err := sliceutils.MapOrError(rest, func(w T) (TV, error) {
		if utils.IsNil(w) {
			return *new(TV), commitments.ErrIsNil.WithMessage("object must not be nil")
		}
		return w.Value(), nil
	})
	if err != nil {
		return *new(T), errs.Wrap(err).WithMessage("invalid witness in rest witnesses")
	}
	out, err := newFunc(algebrautils.Fold(first.Value().Op(second.Value()), restValues...))
	if err != nil {
		return *new(T), errs.Wrap(err).WithMessage("failed to create new witness")
	}
	return out, nil
}

func OpValues[TV algebra.GroupElement[TV]](
	first, second TV,
	rest ...TV,
) (TV, error) {
	if utils.IsNil(first) || utils.IsNil(second) {
		return *new(TV), commitments.ErrIsNil.WithMessage("first and second objects must not be nil")
	}
	if len(rest) > 0 && sliceutils.Any(rest, utils.IsNil[TV]) {
		return *new(TV), commitments.ErrIsNil.WithMessage("objects in rest must not be nil")
	}
	return algebrautils.Fold(first.Op(second), rest...), nil
}
