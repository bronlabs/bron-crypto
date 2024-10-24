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
	ToTagged() error
	fmt.Formatter
}

type WithKeyValueInfoError interface {
	error
	Map() map[string]any
	Value(key string) any
	fmt.Formatter
}

type Tagger interface {
	IsTagging(err error) bool
}

type Tagged0Error interface {
	WithStackError
	Tag() Tag0
}

type Tagged1Error[T any] interface {
	WithStackError
	Tag() Tag1[T]
	Arg() T
}

type Tagged2Error[T, U any] interface {
	WithStackError
	Tag() Tag2[T, U]
	Arg() T
	Arg2() U
}

func New(messages ...string) error {
	return untaggedTag.New(messages...)
}

func Errorf(format string, args ...any) error {
	return untaggedTag.Errorf(format, args...)
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

var _ Tagged0Error = tagged0Error{}

type tagged0Error struct {
	withStackError
	tag Tag0
}

func (e tagged0Error) Tag() Tag0 {
	return e.tag
}

func (e tagged0Error) MarshalText() ([]byte, error) {
	if e.Tag() == untaggedTag {
		return []byte(e.Message()), nil
	}
	if e.Message() == "" {
		return []byte(fmt.Sprintf("[%s]", e.Tag())), nil
	}
	return []byte(fmt.Sprintf("[%s] %s", e.Tag(), e.Message())), nil
}

func (e tagged0Error) Error() string {
	out, _ := e.MarshalText()
	return string(out)
}

func (e tagged0Error) Format(s fmt.State, verb rune) {
	taggedFormatter(e, e.Tag().String(), s, verb)
}

type tagged1Error[T any] struct {
	withStackError
	tag Tag1[T]
	arg T
}

var _ Tagged1Error[any] = tagged1Error[any]{}

func (e1 tagged1Error[T]) Tag() Tag1[T] {
	return e1.tag
}

func (e1 tagged1Error[T]) MarshalText() ([]byte, error) {
	if e1.Tag() == "" {
		return []byte(e1.Message()), nil
	}
	if e1.Message() == "" {
		return []byte(fmt.Sprintf("[%s](%v)", e1.Tag(), e1.Arg())), nil
	}
	return []byte(fmt.Sprintf("[%s](%v) %s", e1.Tag(), e1.Arg(), e1.Message())), nil
}

func (e1 tagged1Error[T]) Format(s fmt.State, verb rune) {
	taggedFormatter(e1, e1.Tag().String(), s, verb)
}

func (e1 tagged1Error[T]) Error() string {
	out, _ := e1.MarshalText()
	return string(out)
}

func (e1 tagged1Error[T]) Arg() T {
	return e1.arg
}

var _ Tagged2Error[any, any] = tagged2Error[any, any]{}

type tagged2Error[T, U any] struct {
	withStackError
	tag  Tag2[T, U]
	arg  T
	arg2 U
}

func (e2 tagged2Error[T, U]) Tag() Tag2[T, U] {
	return e2.tag
}

func (e2 tagged2Error[T, U]) MarshalText() ([]byte, error) {
	if e2.Tag() == "" {
		return []byte(e2.Message()), nil
	}
	if e2.Message() == "" {
		return []byte(fmt.Sprintf("[%s](%v, %v)", e2.Tag(), e2.Arg(), e2.Arg2())), nil
	}
	return []byte(fmt.Sprintf("[%s](%v, %v) %s", e2.Tag(), e2.Arg(), e2.Arg2(), e2.Message())), nil
}

func (e2 tagged2Error[T, U]) Format(s fmt.State, verb rune) {
	taggedFormatter(e2, e2.Tag().String(), s, verb)
}

func (e2 tagged2Error[T, U]) Error() string {
	out, _ := e2.MarshalText()
	return string(out)
}

func (e2 tagged2Error[T, U]) Arg() T {
	return e2.arg
}

func (e2 tagged2Error[T, U]) Arg2() U {
	return e2.arg2
}

func taggedFormatter(e WithStackError, tagMessage string, s fmt.State, verb rune) {
	switch verb {
	case 'v':
		if _, err := io.WriteString(s, e.Error()); err != nil {
			panic(err)
		}
		if s.Flag('+') {
			e.Stack().Format(s, verb)
		}
	case 'T':
		if _, err := io.WriteString(s, tagMessage); err != nil {
			panic(err)
		}
	case 's':
		if _, err := io.WriteString(s, e.Message()); err != nil {
			panic(err)
		}
	case 'q':
		fmt.Fprintf(s, "%q", e.Message())
	}
}
