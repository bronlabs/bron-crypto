package errs2

import (
	"fmt"
	"io"
)

type ErrorWithStack interface {
	error
	Message() string
	Stack() *Stack
	fmt.Formatter
}

type WrappedError interface {
	error
	Unwrap() error
	Cause() error
	fmt.Formatter
}

type ErrorWithKeyValueInfo interface {
	error
	Map() map[string]any
	Value(string) any
	fmt.Formatter
}

type Tagger interface {
	IsTagging(error) bool
}

type TaggedError interface {
	ErrorWithStack
	Tag() Tag
}

type TaggedError1[T any] interface {
	ErrorWithStack
	Tag() Tag1[T]
	Arg() T
}

type TaggedError2[T, U any] interface {
	ErrorWithStack
	Tag() Tag2[T, U]
	Arg() T
	Arg2() U
}

func New(messages ...string) error {
	return UNTAGGED_TAG.New(messages...)
}

func Errorf(format string, args ...any) error {
	return UNTAGGED_TAG.Errorf(format, args...)
}

var _ (ErrorWithStack) = errorWithStack{}

type errorWithStack struct {
	message string
	stack   *Stack
}

func (e errorWithStack) Message() string {
	return e.message
}

func (e errorWithStack) Stack() *Stack {
	return e.stack
}

func (e errorWithStack) Error() string {
	return e.Message()
}

func (e errorWithStack) Format(s fmt.State, verb rune) {
	switch verb {
	case 'v':
		io.WriteString(s, e.Error())
		if s.Flag('+') {
			e.Stack().Format(s, verb)
		}
	case 's':
		io.WriteString(s, e.Error())
	case 'q':
		fmt.Fprintf(s, "%q", e.Message())
	}
}

var _ (TaggedError) = taggedError{}

type taggedError struct {
	errorWithStack
	tag Tag
}

func (e taggedError) Tag() Tag {
	return e.tag
}

func (e taggedError) MarshalText() ([]byte, error) {
	if e.Tag() == UNTAGGED_TAG {
		return []byte(e.Message()), nil
	}
	if e.Message() == "" {
		return []byte(fmt.Sprintf("[%s]", e.Tag())), nil
	}
	return []byte(fmt.Sprintf("[%s] %s", e.Tag(), e.Message())), nil
}

func (e taggedError) Error() string {
	out, _ := e.MarshalText()
	return string(out)
}

func (e taggedError) Format(s fmt.State, verb rune) {
	taggedFormatter(e, e.Tag().String(), s, verb)
}

type taggedError1[T any] struct {
	errorWithStack
	tag Tag1[T]
	arg T
}

var _ (TaggedError1[any]) = taggedError1[any]{}

func (e1 taggedError1[T]) Tag() Tag1[T] {
	return e1.tag
}

func (e1 taggedError1[T]) MarshalText() ([]byte, error) {
	if e1.Tag() == "" {
		return []byte(e1.Message()), nil
	}
	if e1.Message() == "" {
		return []byte(fmt.Sprintf("[%s](%v)", e1.Tag(), e1.Arg())), nil
	}
	return []byte(fmt.Sprintf("[%s](%v) %s", e1.Tag(), e1.Arg(), e1.Message())), nil
}

func (e taggedError1[T]) Format(s fmt.State, verb rune) {
	taggedFormatter(e, e.Tag().String(), s, verb)
}

func (e1 taggedError1[T]) Error() string {
	out, _ := e1.MarshalText()
	return string(out)
}

func (e1 taggedError1[T]) Arg() T {
	return e1.arg
}

var _ (TaggedError2[any, any]) = taggedError2[any, any]{}

type taggedError2[T, U any] struct {
	errorWithStack
	tag  Tag2[T, U]
	arg  T
	arg2 U
}

func (e2 taggedError2[T, U]) Tag() Tag2[T, U] {
	return e2.tag
}

func (e2 taggedError2[T, U]) MarshalText() ([]byte, error) {
	if e2.Tag() == "" {
		return []byte(e2.Message()), nil
	}
	if e2.Message() == "" {
		return []byte(fmt.Sprintf("[%s](%v, %v)", e2.Tag(), e2.Arg(), e2.Arg2())), nil
	}
	return []byte(fmt.Sprintf("[%s](%v, %v) %s", e2.Tag(), e2.Arg(), e2.Arg2(), e2.Message())), nil
}

func (e taggedError2[T, U]) Format(s fmt.State, verb rune) {
	taggedFormatter(e, e.Tag().String(), s, verb)
}

func (e2 taggedError2[T, U]) Error() string {
	out, _ := e2.MarshalText()
	return string(out)
}

func (e2 taggedError2[T, U]) Arg() T {
	return e2.arg
}

func (e2 taggedError2[T, U]) Arg2() U {
	return e2.arg2
}

func taggedFormatter(e ErrorWithStack, tagMessage string, s fmt.State, verb rune) {
	switch verb {
	case 'v':
		io.WriteString(s, e.Error())
		if s.Flag('+') {
			e.Stack().Format(s, verb)
		}
	case 'T':
		io.WriteString(s, tagMessage)
	case 's':
		io.WriteString(s, e.Message())
	case 'q':
		fmt.Fprintf(s, "%q", e.Message())
	}
}
