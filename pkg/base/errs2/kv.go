package errs2

import (
	"fmt"
	"maps"
)

var _ WithKeyValueInfoError = withKeyValueError{}

func Attach(err error, kv map[string]any) error {
	return &withKeyValueError{
		error: err,
		kv:    maps.Clone(kv),
	}
}

type withKeyValueError struct {
	error
	kv map[string]any
}

func (e withKeyValueError) Format(s fmt.State, verb rune) {
	switch verb {
	case 'v':
		fmt.Fprintf(s, "%v", e.error)
		if s.Flag('#') {
			fmt.Fprintf(s, "\n%v", e.kv)
		}
	case 'q':
		fmt.Fprintf(s, "%q", e.error)
	case 's':
		fmt.Fprintf(s, "%s", e.error)
		if s.Flag('#') {
			fmt.Fprintf(s, "\n%v", e.kv)
		}
	}
}

func (e withKeyValueError) Map() map[string]any {
	return maps.Clone(e.kv)
}

func (e withKeyValueError) Value(key string) any {
	return e.kv[key]
}

var _ tag0Builder = tagged0WithKeyValueErrorBuilder{}

type tagged0WithKeyValueErrorBuilder struct {
	tag Tag0
	kv  map[string]any
}

func (t tagged0WithKeyValueErrorBuilder) Errorf(format string, args ...any) error {
	return withKeyValueError{
		error: t.tag.Errorf(format, args...),
		kv:    t.kv,
	}
}

func (t tagged0WithKeyValueErrorBuilder) New(messages ...string) error {
	return withKeyValueError{
		error: t.tag.New(messages...),
		kv:    t.kv,
	}
}

func (t tagged0WithKeyValueErrorBuilder) Wrapf(err error, format string, args ...any) error {
	return withKeyValueError{
		error: t.tag.Wrapf(err, format, args...),
		kv:    t.kv,
	}
}

func (t tagged0WithKeyValueErrorBuilder) Wrap(err error, messages ...string) error {
	return withKeyValueError{
		error: t.tag.Wrap(err, messages...),
		kv:    t.kv,
	}
}

var _ tag1Builder[any] = tagged1WithKeyValueErrorBuilder[any]{}

type tagged1WithKeyValueErrorBuilder[T any] struct {
	tag Tag1[T]
	kv  map[string]any
}

func (t tagged1WithKeyValueErrorBuilder[T]) Errorf(arg T, format string, args ...any) error {
	return withKeyValueError{
		error: t.tag.Errorf(arg, format, args...),
		kv:    t.kv,
	}
}

func (t tagged1WithKeyValueErrorBuilder[T]) New(arg T, messages ...string) error {
	return withKeyValueError{
		error: t.tag.New(arg, messages...),
		kv:    t.kv,
	}
}

func (t tagged1WithKeyValueErrorBuilder[T]) Wrapf(err error, arg T, format string, args ...any) error {
	return withKeyValueError{
		error: t.tag.Wrapf(err, arg, format, args...),
		kv:    t.kv,
	}
}

func (t tagged1WithKeyValueErrorBuilder[T]) Wrap(err error, arg T, messages ...string) error {
	return withKeyValueError{
		error: t.tag.Wrap(err, arg, messages...),
		kv:    t.kv,
	}
}

type tagged2WithKeyValueErrorBuilder[T, U any] struct {
	tag Tag2[T, U]
	kv  map[string]any
}

func (t tagged2WithKeyValueErrorBuilder[T, U]) Errorf(arg T, arg2 U, format string, args ...any) error {
	return withKeyValueError{
		error: t.tag.Errorf(arg, arg2, format, args...),
		kv:    t.kv,
	}
}

func (t tagged2WithKeyValueErrorBuilder[T, U]) New(arg T, arg2 U, messages ...string) error {
	return withKeyValueError{
		error: t.tag.New(arg, arg2, messages...),
		kv:    t.kv,
	}
}

func (t tagged2WithKeyValueErrorBuilder[T, U]) Wrapf(err error, arg T, arg2 U, format string, args ...any) error {
	return withKeyValueError{
		error: t.tag.Wrapf(err, arg, arg2, format, args...),
		kv:    t.kv,
	}
}

func (t tagged2WithKeyValueErrorBuilder[T, U]) Wrap(err error, arg T, arg2 U, messages ...string) error {
	return withKeyValueError{
		error: t.tag.Wrap(err, arg, arg2, messages...),
		kv:    t.kv,
	}
}
