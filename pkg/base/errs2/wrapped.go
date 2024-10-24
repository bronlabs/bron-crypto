package errs2

import (
	"fmt"
)

func Wrap(err error, message string) error {
	return wrapped0Error{
		//nolint:errorlint,forcetypeassert // error package internals
		tagged0Error: untaggedTag.Errorf("%s", message).(tagged0Error),
		underlying:   err,
	}
}

func Wrapf(err error, format string, args ...any) error {
	return wrapped0Error{
		//nolint:errorlint,forcetypeassert // error package internals
		tagged0Error: untaggedTag.Errorf(format, args...).(tagged0Error),
		underlying:   err,
	}
}

func UnwrapAll(err error) []error {
	//nolint:errorlint // error package internals
	top, ok := err.(WrappedError)
	if !ok {
		return []error{err}
	}
	errs := []error{top}
	current := top.Unwrap()
	for current != nil {
		errs = append(errs, current)
		//nolint:errorlint // error package internals
		wrappedCurrent, ok := current.(WrappedError)
		if !ok {
			break
		}
		current = wrappedCurrent.Unwrap()
	}
	return errs
}

func Has(errorChain error, tag Tagger) bool {
	return Extract(errorChain, tag) != nil
}

func Extract(errorChain error, tag Tagger) error {
	chain := UnwrapAll(errorChain)
	for _, err := range chain {
		if tag.IsTagging(err) {
			return err
		}
	}
	return nil
}

var _ WrappedError = wrapped0Error{}

type wrapped0Error struct {
	tagged0Error
	underlying error
}

func (w0 wrapped0Error) Unwrap() error {
	return w0.underlying
}

func (w0 wrapped0Error) Cause() error {
	return cause(w0)
}

func (w0 wrapped0Error) Format(s fmt.State, verb rune) {
	directive := "%" + string(verb)
	wrappedFormatter(fmt.Sprintf(directive, w0.tagged0Error), w0, s, verb)
}

func (w0 wrapped0Error) ToTagged() error {
	return w0.tagged0Error
}

var _ WrappedError = wrapped1Error[any]{}

type wrapped1Error[T any] struct {
	tagged1Error[T]
	underlying error
}

func (w1 wrapped1Error[T]) Unwrap() error {
	return w1.underlying
}

func (w1 wrapped1Error[T]) Cause() error {
	return cause(w1)
}

func (w1 wrapped1Error[T]) Format(s fmt.State, verb rune) {
	directive := "%" + string(verb)
	wrappedFormatter(fmt.Sprintf(directive, w1.tagged1Error), w1, s, verb)
}

func (w1 wrapped1Error[T]) ToTagged() error {
	return w1.tagged1Error
}

var _ WrappedError = wrapped2Error[any, any]{}

type wrapped2Error[T any, U any] struct {
	tagged2Error[T, U]
	underlying error
}

func (w2 wrapped2Error[T, U]) Unwrap() error {
	return w2.underlying
}

func (w2 wrapped2Error[T, U]) Cause() error {
	return cause(w2)
}

func (w2 wrapped2Error[T, U]) Format(s fmt.State, verb rune) {
	directive := "%" + string(verb)
	wrappedFormatter(fmt.Sprintf(directive, w2.tagged2Error), w2, s, verb)
}

func (w2 wrapped2Error[T, U]) ToTagged() error {
	return w2.tagged2Error
}

func cause(err WrappedError) error {
	chain := UnwrapAll(err)
	return chain[len(chain)-1]
}

func wrappedFormatter(formattedSelf string, err WrappedError, s fmt.State, verb rune) {
	switch verb {
	case 'v':
		if s.Flag('0') {
			fmt.Fprintf(s, "%v", err.Cause())
		} else {
			chain := UnwrapAll(err)
			for i, err := range chain {
				//nolint:errorlint // error package internals
				if weErr, ok := err.(WrappedError); ok {
					fmt.Fprintf(s, "%v\n", weErr.ToTagged())
				} else {
					fmt.Fprintf(s, "%v\n", err)
				}

				if s.Flag('+') {
					//nolint:errorlint // error package internals
					if weErr, ok := err.(WithStackError); ok {
						weErr.Stack().Format(s, verb)
					}
				}
				if i < len(chain)-1 {
					fmt.Fprintf(s, "\n\nCaused by:\n")
				}
			}
		}
	case 'T':
		fmt.Fprintf(s, "%s <- %T", formattedSelf, err.Unwrap())
	case 'q', 's':
		fmt.Fprintf(s, "%s", formattedSelf)
	}
}
