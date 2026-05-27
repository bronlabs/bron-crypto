package algebrautils

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
)

// Op performs a fold over the given group elements, applying the group operation.
// It validates that all inputs are non-nil and belong to the group, and uses newFunc to construct the output object from the resulting group element.
// It is used in internal implementations of commitment/encryption keys.
func Op[
	T base.Transparent[TV], TV algebra.GroupElement[TV],
](
	newFunc func(TV) (T, error),
	group algebra.Group[TV],
	first, second T,
	rest ...T,
) (T, error) {
	if utils.IsNil(first) || utils.IsNil(second) {
		return *new(T), ErrIsNil.WithMessage("first and second objects must not be nil")
	}
	if !group.Contains(first.Value()) || !group.Contains(second.Value()) {
		return *new(T), ErrInvalidArgument.WithMessage("first and second objects must be in the group")
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
	if sliceutils.Any(restValues, func(v TV) bool { return !group.Contains(v) }) {
		return *new(T), ErrInvalidArgument.WithMessage("all objects must be in the group")
	}
	out, err := newFunc(Fold(first.Value().Op(second.Value()), restValues...))
	if err != nil {
		return *new(T), errs.Wrap(err).WithMessage("failed to create new object")
	}
	return out, nil
}

// OpValues performs a fold over the given group elements, applying the group operation.
// It validates that all inputs are non-nil and belong to the group, and returns the resulting group element.
// It is used in internal implementations of commitment/encryption keys.
func OpValues[TV algebra.GroupElement[TV]](
	group algebra.Group[TV],
	first, second TV,
	rest ...TV,
) (TV, error) {
	if utils.IsNil(first) || utils.IsNil(second) {
		return *new(TV), ErrIsNil.WithMessage("first and second objects must not be nil")
	}
	if !group.Contains(first) || !group.Contains(second) {
		return *new(TV), ErrInvalidArgument.WithMessage("first and second objects must be in the group")
	}
	if len(rest) > 0 && sliceutils.Any(rest, utils.IsNil[TV]) {
		return *new(TV), ErrIsNil.WithMessage("objects in rest must not be nil")
	}
	if len(rest) > 0 && !sliceutils.All(rest, group.Contains) {
		return *new(TV), ErrInvalidArgument.WithMessage("objects in rest must be in group")
	}
	return Fold(first.Op(second), rest...), nil
}
