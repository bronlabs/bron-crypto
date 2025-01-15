package algebra

import "github.com/bronlabs/krypton-primitives/pkg/base/errs"

func Hyper[S Structure, E Element](monoid Monoid[S, E], operator BinaryOperator[E]) (BinaryOperator[E], error) {
	identity, err := monoid.Identity(operator)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not derive identity")
	}
	return &hyperOperator[E]{
		prevGrade: operator,
		identity:  identity,
		isEqual: func(x, y E) (bool, error) {
			xx, err := wrapInMonoid[S, E](x)
			if err != nil {
				return false, err
			}
			if _, err := wrapInMonoid[S, E](y); err != nil {
				return false, err
			}
			return xx.Equal(y), nil
		},
		copier: func(x E) (E, error) {
			xx, err := wrapInMonoid[S, E](x)
			if err != nil {
				return *new(E), err
			}
			return xx.Clone(), err
		},
	}, nil
}

var _ BinaryOperator[Element] = (*hyperOperator[Element])(nil)

type hyperOperator[E Element] struct {
	prevGrade BinaryOperator[E]
	identity  E
	copier    func(x E) (E, error)
	isEqual   func(x, y E) (bool, error)
}

func (h *hyperOperator[_]) Arity() uint {
	return h.prevGrade.Arity()
}

func (h *hyperOperator[E]) Map(x, y E) (E, error) {
	yIsIdentity, err := h.isEqual(y, h.identity)
	if err != nil {
		return *new(E), errs.WrapFailed(err, "could not check if y is identity")
	}
	if yIsIdentity {
		return x, nil
	}
	cursor, err := h.copier(h.identity)
	if err != nil {
		return *new(E), errs.WrapFailed(err, "could not copy identity element to cursor")
	}
	result, err := h.copier(x)
	if err != nil {
		return *new(E), errs.WrapFailed(err, "could not copy x")
	}
	cursorIsEqualToY := false
	for !cursorIsEqualToY {
		result, err = h.prevGrade.Map(result, x)
		if err != nil {
			return *new(E), errs.WrapFailed(err, "could not apply lower grade operator")
		}
		cursor, err = h.prevGrade.Map(cursor, h.identity)
		if err != nil {
			return *new(E), errs.WrapFailed(err, "could not increment cursor")
		}
		cursorIsEqualToY, err = h.isEqual(cursor, y)
		if err != nil {
			return *new(E), errs.WrapFailed(err, "could not check if cursor is equal to y")
		}
	}
	return result, nil
}

func wrapInMonoid[MonoidType Structure, MonoidElementType Element](x Element) (MonoidElement[MonoidType, MonoidElementType], error) {
	out, ok := x.(MonoidElement[MonoidType, MonoidElementType])
	if !ok {
		return nil, errs.NewIsNil("input is not a monoid element")
	}
	return out, nil
}
