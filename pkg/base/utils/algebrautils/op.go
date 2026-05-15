package algebrautils

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
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
		return *new(T), ErrIsNil.WithMessage("first and second objects must not be nil")
	}
	restValues, err := sliceutils.MapOrError(rest, func(w T) (TV, error) {
		if utils.IsNil(w) {
			return *new(TV), ErrIsNil.WithMessage("object must not be nil")
		}
		return w.Value(), nil
	})
	if err != nil {
		return *new(T), errs.Wrap(err).WithMessage("invalid object in rest ")
	}
	out, err := newFunc(Fold(first.Value().Op(second.Value()), restValues...))
	if err != nil {
		return *new(T), errs.Wrap(err).WithMessage("failed to create new object")
	}
	return out, nil
}

func OpValues[TV algebra.GroupElement[TV]](
	first, second TV,
	rest ...TV,
) (TV, error) {
	if utils.IsNil(first) || utils.IsNil(second) {
		return *new(TV), ErrIsNil.WithMessage("first and second objects must not be nil")
	}
	if len(rest) > 0 && sliceutils.Any(rest, utils.IsNil[TV]) {
		return *new(TV), ErrIsNil.WithMessage("objects in rest must not be nil")
	}
	return Fold(first.Op(second), rest...), nil
}
