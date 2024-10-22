package errs2

import (
	"fmt"
)

func Wrap(err error, message string) error {
	return wrappedError{
		taggedError: UNTAGGED_TAG.Errorf(message).(taggedError),
		underlying:  err,
	}
}

func Wrapf(err error, format string, args ...any) error {
	return wrappedError{
		taggedError: UNTAGGED_TAG.Errorf(format, args...).(taggedError),
		underlying:  err,
	}
}

func UnwrapAll(err error) []error {
	top, ok := err.(WrappedError)
	if !ok {
		return []error{err}
	}
	errs := []error{top}
	current := top.Unwrap()
	for current != nil {
		errs = append(errs, current)
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

var _ (WrappedError) = wrappedError{}

type wrappedError struct {
	taggedError
	underlying error
}

func (we wrappedError) Unwrap() error {
	return we.underlying
}

func (we wrappedError) Cause() error {
	return cause(we)
}

func (we wrappedError) Format(s fmt.State, verb rune) {
	directive := "%" + string(verb)
	wrappedFormatter(fmt.Sprintf(directive, we.taggedError), we, s, verb)
}

type wrappedError1[T any] struct {
	taggedError1[T]
	underlying error
}

func (we wrappedError1[T]) Unwrap() error {
	return we.underlying
}

func (we wrappedError1[T]) Cause() error {
	return cause(we)
}

func (we wrappedError1[T]) Format(s fmt.State, verb rune) {
	directive := "%" + string(verb)
	wrappedFormatter(fmt.Sprintf(directive, we.taggedError1), we, s, verb)
}

type wrappedError2[T any, U any] struct {
	taggedError2[T, U]
	underlying error
}

func (we wrappedError2[T, U]) Unwrap() error {
	return we.underlying
}

func (we wrappedError2[T, U]) Cause() error {
	return cause(we)
}

func (we wrappedError2[T, U]) Format(s fmt.State, verb rune) {
	directive := "%" + string(verb)
	wrappedFormatter(fmt.Sprintf(directive, we.taggedError2), we, s, verb)
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
				fmt.Fprintf(s, "%v\n", err)
				if s.Flag('+') {
					if weErr, ok := err.(ErrorWithStack); ok {
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
