package network

import "github.com/bronlabs/errs-go/errs"

// Runner executes a networked protocol using a Router and returns its output.
type Runner[O any] interface {
	Run(rt *Router) (O, error)
}

func NewSafeRunner[O any](r Runner[O]) Runner[O] {
	return &safeRunner[O]{
		r: r,
	}
}

type safeRunner[O any] struct {
	r Runner[O]
}

func (r *safeRunner[O]) Run(rt *Router) (out O, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			switch v := recovered.(type) {
			case error:
				err = errs.Wrap(v).WithMessage("runner panicked")
			default:
				err = errs.New("runner panicked: %v", v)
			}
		}
	}()

	//nolint:wrapcheck // intentionally not wrapping the error
	return r.r.Run(rt)
}
