package errs2

import (
	"fmt"
	"io"
)

type WithStackError interface {
	error
	Message() string
	Stack() *Stack
	fmt.Formatter
}

type WrappedError interface {
	error
	Unwrap() error
	Cause() error
	WrappingError() error
	fmt.Formatter
}

type WithKeyValueInfoError interface {
	error
	Map() map[string]any
	Value(key string) any
	fmt.Formatter
}

type Kinder interface {
	IsKinded(err error) bool
}

type KindedError interface {
	WithStackError
	Kind() Kind
}

type Kinded1Error[T any] interface {
	WithStackError
	Kind() Kind1[T]
	Arg() T
}

type Kinded2Error[T, U any] interface {
	WithStackError
	Kind() Kind2[T, U]
	Arg() T
	Arg2() U
}

func New(messages ...string) error {
	return NoKind.New(messages...)
}

func Errorf(format string, args ...any) error {
	return NoKind.Errorf(format, args...)
}

var _ WithStackError = withStackError{}

type withStackError struct {
	message string
	stack   *Stack
}

func (e withStackError) Message() string {
	return e.message
}

func (e withStackError) Stack() *Stack {
	return e.stack
}

func (e withStackError) Error() string {
	return e.Message()
}

func (e withStackError) Format(s fmt.State, verb rune) {
	switch verb {
	case 'v':
		if _, err := io.WriteString(s, e.Error()); err != nil {
			panic(err)
		}
		if s.Flag('+') {
			e.Stack().Format(s, verb)
		}
	case 's':
		if _, err := io.WriteString(s, e.Error()); err != nil {
			panic(err)
		}
	case 'q':
		fmt.Fprintf(s, "%q", e.Message())
	}
}

var _ KindedError = kindedError{}

type kindedError struct {
	withStackError
	kind Kind
}

func (e kindedError) Kind() Kind {
	return e.kind
}

func (e kindedError) MarshalText() ([]byte, error) {
	if e.Kind() == NoKind {
		return []byte(e.Message()), nil
	}
	if e.Message() == "" {
		return []byte(fmt.Sprintf("[%s]", e.Kind())), nil
	}
	return []byte(fmt.Sprintf("[%s] %s", e.Kind(), e.Message())), nil
}

func (e kindedError) Error() string {
	out, _ := e.MarshalText()
	return string(out)
}

func (e kindedError) Format(s fmt.State, verb rune) {
	formatKindedError(e, s, verb)
}

type kinded1Error[T any] struct {
	withStackError
	kind Kind1[T]
	arg  T
}

var _ Kinded1Error[any] = kinded1Error[any]{}

func (e1 kinded1Error[T]) Kind() Kind1[T] {
	return e1.kind
}

func (e1 kinded1Error[T]) MarshalText() ([]byte, error) {
	if e1.Kind() == "" {
		return []byte(e1.Message()), nil
	}
	if e1.Message() == "" {
		return []byte(fmt.Sprintf("[%s](%v)", e1.Kind(), e1.Arg())), nil
	}
	return []byte(fmt.Sprintf("[%s](%v) %s", e1.Kind(), e1.Arg(), e1.Message())), nil
}

func (e1 kinded1Error[T]) Format(s fmt.State, verb rune) {
	formatKindedError(e1, s, verb)
}

func (e1 kinded1Error[T]) Error() string {
	out, _ := e1.MarshalText()
	return string(out)
}

func (e1 kinded1Error[T]) Arg() T {
	return e1.arg
}

var _ Kinded2Error[any, any] = kinded2Error[any, any]{}

type kinded2Error[T, U any] struct {
	withStackError
	kind Kind2[T, U]
	arg  T
	arg2 U
}

func (e2 kinded2Error[T, U]) Kind() Kind2[T, U] {
	return e2.kind
}

func (e2 kinded2Error[T, U]) MarshalText() ([]byte, error) {
	if e2.Kind() == "" {
		return []byte(e2.Message()), nil
	}
	if e2.Message() == "" {
		return []byte(fmt.Sprintf("[%s](%v, %v)", e2.Kind(), e2.Arg(), e2.Arg2())), nil
	}
	return []byte(fmt.Sprintf("[%s](%v, %v) %s", e2.Kind(), e2.Arg(), e2.Arg2(), e2.Message())), nil
}

func (e2 kinded2Error[T, U]) Format(s fmt.State, verb rune) {
	formatKindedError(e2, s, verb)
}

func (e2 kinded2Error[T, U]) Error() string {
	out, _ := e2.MarshalText()
	return string(out)
}

func (e2 kinded2Error[T, U]) Arg() T {
	return e2.arg
}

func (e2 kinded2Error[T, U]) Arg2() U {
	return e2.arg2
}

func formatKindedError(e WithStackError, s fmt.State, verb rune) {
	switch verb {
	case 'v':
		if _, err := io.WriteString(s, e.Error()); err != nil {
			panic(err)
		}
		if s.Flag('+') {
			e.Stack().Format(s, verb)
		}
	case 's':
		if _, err := io.WriteString(s, e.Message()); err != nil {
			panic(err)
		}
	case 'q':
		fmt.Fprintf(s, "%q", e.Message())
	}
}
