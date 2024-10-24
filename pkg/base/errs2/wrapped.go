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
	top, ok := err.(Wrapped0Error)
	if !ok {
		return []error{err}
	}
	errs := []error{top}
	current := top.Unwrap()
	for current != nil {
		errs = append(errs, current)
		//nolint:errorlint // error package internals
		wrappedCurrent, ok := current.(Wrapped0Error)
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

var _ Wrapped0Error = wrapped0Error{}

type wrapped0Error struct {
	tagged0Error
	underlying error
}

func (we wrapped0Error) Unwrap() error {
	return we.underlying
}

func (we wrapped0Error) Cause() error {
	return cause(we)
}

func (we wrapped0Error) Format(s fmt.State, verb rune) {
	directive := "%" + string(verb)
	wrappedFormatter(fmt.Sprintf(directive, we.tagged0Error), we, s, verb)
}

type wrapped1Error[T any] struct {
	tagged1Error[T]
	underlying error
}

func (we wrapped1Error[T]) Unwrap() error {
	return we.underlying
}

func (we wrapped1Error[T]) Cause() error {
	return cause(we)
}

func (we wrapped1Error[T]) Format(s fmt.State, verb rune) {
	directive := "%" + string(verb)
	wrappedFormatter(fmt.Sprintf(directive, we.tagged1Error), we, s, verb)
}

type wrapped2Error[T any, U any] struct {
	tagged2Error[T, U]
	underlying error
}

func (we wrapped2Error[T, U]) Unwrap() error {
	return we.underlying
}

func (we wrapped2Error[T, U]) Cause() error {
	return cause(we)
}

func (we wrapped2Error[T, U]) Format(s fmt.State, verb rune) {
	directive := "%" + string(verb)
	wrappedFormatter(fmt.Sprintf(directive, we.tagged2Error), we, s, verb)
}

func cause(err Wrapped0Error) error {
	chain := UnwrapAll(err)
	return chain[len(chain)-1]
}

func wrappedFormatter(formattedSelf string, err Wrapped0Error, s fmt.State, verb rune) {
	switch verb {
	case 'v':
		if s.Flag('0') {
			fmt.Fprintf(s, "%v", err.Cause())
		} else {
			chain := UnwrapAll(err)
			for i, err := range chain {
				fmt.Fprintf(s, "%v\n", err)
				if s.Flag('+') {
					//nolint:errorlint // error package internals
					if weErr, ok := err.(WithStackError); ok {
						weErr.Stack().Format(s, verb)
					}
				}
				if i < len(chain)-1 {
					fmt.Fprintf(s, "\n -> \n")
				}
			}
		}
	case 'T':
		fmt.Fprintf(s, "%s <- %T", formattedSelf, err.Unwrap())
	case 'q', 's':
		fmt.Fprintf(s, "%s", formattedSelf)
	}
}
