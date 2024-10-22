package errs2

import (
	"fmt"
	"maps"
)

var _ ErrorWithKeyValueInfo = errorWithKeyValue{}

func Attach(err error, kv map[string]any) error {
	return &errorWithKeyValue{
		error: err,
		kv:    maps.Clone(kv),
	}
}

type errorWithKeyValue struct {
	error
	kv map[string]any
}

func (e errorWithKeyValue) Format(s fmt.State, verb rune) {
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

func (e errorWithKeyValue) Map() map[string]any {
	return maps.Clone(e.kv)
}

func (e errorWithKeyValue) Value(key string) any {
	return e.kv[key]
}

var _ tagBuilder = taggedErrorWithKeyValueBuilder{}

type taggedErrorWithKeyValueBuilder struct {
	tag Tag
	kv  map[string]any
}

func (t taggedErrorWithKeyValueBuilder) Errorf(format string, args ...any) error {
	return errorWithKeyValue{
		error: t.tag.Errorf(format, args...),
		kv:    t.kv,
	}
}

func (t taggedErrorWithKeyValueBuilder) New(messages ...string) error {
	return errorWithKeyValue{
		error: t.tag.New(messages...),
		kv:    t.kv,
	}
}

func (t taggedErrorWithKeyValueBuilder) Wrapf(err error, format string, args ...any) error {
	return errorWithKeyValue{
		error: t.tag.Wrapf(err, format, args...),
		kv:    t.kv,
	}
}

func (t taggedErrorWithKeyValueBuilder) Wrap(err error, messages ...string) error {
	return errorWithKeyValue{
		error: t.tag.Wrap(err, messages...),
		kv:    t.kv,
	}
}

var _ tag1Builder[any] = taggedError1WithKeyValueBuilder[any]{}

type taggedError1WithKeyValueBuilder[T any] struct {
	tag Tag1[T]
	kv  map[string]any
}

func (t taggedError1WithKeyValueBuilder[T]) Errorf(arg T, format string, args ...any) error {
	return errorWithKeyValue{
		error: t.tag.Errorf(arg, format, args...),
		kv:    t.kv,
	}
}

func (t taggedError1WithKeyValueBuilder[T]) New(arg T, messages ...string) error {
	return errorWithKeyValue{
		error: t.tag.New(arg, messages...),
		kv:    t.kv,
	}
}

func (t taggedError1WithKeyValueBuilder[T]) Wrapf(err error, arg T, format string, args ...any) error {
	return errorWithKeyValue{
		error: t.tag.Wrapf(err, arg, format, args...),
		kv:    t.kv,
	}
}

func (t taggedError1WithKeyValueBuilder[T]) Wrap(err error, arg T, messages ...string) error {
	return errorWithKeyValue{
		error: t.tag.Wrap(err, arg, messages...),
		kv:    t.kv,
	}
}

type taggedError2WithKeyValueBuilder[T, U any] struct {
	tag Tag2[T, U]
	kv  map[string]any
}

func (t taggedError2WithKeyValueBuilder[T, U]) Errorf(arg T, arg2 U, format string, args ...any) error {
	return errorWithKeyValue{
		error: t.tag.Errorf(arg, arg2, format, args...),
		kv:    t.kv,
	}
}

func (t taggedError2WithKeyValueBuilder[T, U]) New(arg T, arg2 U, messages ...string) error {
	return errorWithKeyValue{
		error: t.tag.New(arg, arg2, messages...),
		kv:    t.kv,
	}
}

func (t taggedError2WithKeyValueBuilder[T, U]) Wrapf(err error, arg T, arg2 U, format string, args ...any) error {
	return errorWithKeyValue{
		error: t.tag.Wrapf(err, arg, arg2, format, args...),
		kv:    t.kv,
	}
}

func (t taggedError2WithKeyValueBuilder[T, U]) Wrap(err error, arg T, arg2 U, messages ...string) error {
	return errorWithKeyValue{
		error: t.tag.Wrap(err, arg, arg2, messages...),
		kv:    t.kv,
	}
}
