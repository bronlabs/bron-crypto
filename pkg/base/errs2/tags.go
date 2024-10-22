package errs2

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
)

const UNTAGGED_TAG = Tag("")

func init() {
	RegisterTag(UNTAGGED_TAG, "")
}

func IsTagged(err error) bool {
	if err == nil {
		return false
	}
	t := reflect.TypeOf(err)
	method, exists := t.MethodByName("Tag")
	if !exists {
		return false
	}

	if method.Type.NumIn() != 1 {
		return false
	}

	tagMethodReturnType := method.Type.Out(0)
	currentPkg := runtime.FuncForPC(reflect.ValueOf(IsTagged).Pointer()).Name()
	currentPkg = currentPkg[:len(currentPkg)-len(".IsTagged")]
	fmt.Println(tagMethodReturnType.PkgPath(), currentPkg)
	return tagMethodReturnType.PkgPath() == currentPkg
}

func IsTaggedWith(err error, tag Tagger) bool {
	return tag.IsTagging(err)
}

var _ Tagger = Tag("")

type Tag string

func (t Tag) String() string {
	return strings.ReplaceAll(
		strings.ToUpper(string(t)),
		" ", "_",
	)
}

func (t Tag) Errorf(format string, args ...any) error {
	return taggedError{
		tag: t,
		errorWithStack: errorWithStack{
			message: fmt.Sprintf(format, args...),
			stack:   callers(),
		},
	}
}

func (t Tag) New(messages ...string) error {
	return t.Errorf(parseMessages(t.String(), messages))
}

func (t Tag) Wrapf(err error, format string, args ...any) error {
	return wrappedError{
		taggedError: t.Errorf(format, args...).(taggedError),
		underlying:  err,
	}
}

func (t Tag) Wrap(err error, messages ...string) error {
	return t.Wrapf(err, parseMessages(t.String(), messages))
}

func (t Tag) With(keyValue map[string]any) taggedErrorWithKeyValueBuilder {
	return taggedErrorWithKeyValueBuilder{
		tag: t,
		kv:  keyValue,
	}
}

func (t Tag) IsTagging(err error) bool {
	if tErr, ok := err.(taggedError); ok {
		return tErr.tag == t
	}
	if wrappedErr, ok := err.(wrappedError); ok {
		return t.IsTagging(wrappedErr.taggedError)
	}
	if kvError, ok := err.(errorWithKeyValue); ok {
		return t.IsTagging(kvError.error)
	}
	return false
}

var _ Tagger = Tag1[any]("")

type Tag1[T any] string

func (t1 Tag1[T]) String() string {
	return fmt.Sprintf(
		"%s<%T>",
		strings.ReplaceAll(strings.ToUpper(string(t1)), " ", "_"),
		*new(T),
	)
}

func (t1 Tag1[T]) Errorf(arg T, format string, args ...any) error {
	return taggedError1[T]{
		errorWithStack: errorWithStack{
			message: fmt.Sprintf(format, args...),
			stack:   callers(),
		},
		tag: t1,
		arg: arg,
	}
}

func (t1 Tag1[T]) New(arg T, messages ...string) error {
	return t1.Errorf(arg, parseMessages(t1.String(), messages))
}

func (t1 Tag1[T]) Wrapf(err error, arg T, format string, args ...any) error {
	return wrappedError1[T]{
		taggedError1: t1.Errorf(arg, format, args...).(taggedError1[T]),
		underlying:   err,
	}
}

func (t1 Tag1[T]) Wrap(err error, arg T, messages ...string) error {
	return t1.Wrapf(err, arg, parseMessages(t1.String(), messages))
}

func (t1 Tag1[T]) With(keyValue map[string]any) taggedError1WithKeyValueBuilder[T] {
	return taggedError1WithKeyValueBuilder[T]{
		tag: t1,
		kv:  keyValue,
	}
}

func (t1 Tag1[T]) IsTagging(err error) bool {
	if tErr, ok := err.(taggedError1[T]); ok {
		return tErr.tag == t1
	}
	if wrappedErr, ok := err.(wrappedError1[T]); ok {
		return t1.IsTagging(wrappedErr.taggedError1)
	}
	if kvError, ok := err.(errorWithKeyValue); ok {
		return t1.IsTagging(kvError.error)
	}
	return false
}

var _ Tagger = Tag2[any, any]("")

type Tag2[T, U any] string

func (t2 Tag2[T, U]) New(arg1 T, arg2 U, messages ...string) error {
	return t2.Errorf(arg1, arg2, parseMessages(t2.String(), messages))
}

func (t2 Tag2[T, U]) Errorf(arg1 T, arg2 U, format string, args ...any) error {
	return taggedError2[T, U]{
		errorWithStack: errorWithStack{
			message: fmt.Sprintf(format, args...),
			stack:   callers(),
		},
		tag:  t2,
		arg:  arg1,
		arg2: arg2,
	}
}

func (t Tag2[T, U]) String() string {
	return fmt.Sprintf(
		"%s<%T, %T>",
		strings.ReplaceAll(strings.ToUpper(string(t)), " ", "_"),
		*new(T),
		*new(U),
	)
}

func (t2 Tag2[T, U]) Wrapf(err error, arg1 T, arg2 U, format string, args ...any) error {
	return wrappedError2[T, U]{
		taggedError2: t2.Errorf(arg1, arg2, format, args...).(taggedError2[T, U]),
		underlying:   err,
	}
}

func (t2 Tag2[T, U]) Wrap(err error, arg1 T, arg2 U, messages ...string) error {
	return t2.Wrapf(err, arg1, arg2, parseMessages(t2.String(), messages))
}

func (t2 Tag2[T, U]) With(keyValue map[string]any) taggedError2WithKeyValueBuilder[T, U] {
	return taggedError2WithKeyValueBuilder[T, U]{
		tag: t2,
		kv:  keyValue,
	}
}

func (t2 Tag2[T, U]) IsTagging(err error) bool {
	if tErr, ok := err.(taggedError2[T, U]); ok {
		return tErr.tag == t2
	}
	if wrappedErr, ok := err.(wrappedError2[T, U]); ok {
		return t2.IsTagging(wrappedErr.taggedError2)
	}
	if kvError, ok := err.(errorWithKeyValue); ok {
		return t2.IsTagging(kvError.error)
	}
	return false
}

type tagBuilder interface {
	Errorf(format string, args ...any) error
	New(messages ...string) error
	Wrapf(err error, format string, args ...any) error
	Wrap(err error, messages ...string) error
}

var _ tagBuilder = Tag("")

type tag1Builder[T any] interface {
	Errorf(arg T, format string, args ...any) error
	New(arg T, messages ...string) error
	Wrapf(err error, arg T, format string, args ...any) error
	Wrap(err error, arg T, messages ...string) error
}

var _ tag1Builder[any] = Tag1[any]("")

type tag2Builder[T, U any] interface {
	Errorf(arg1 T, arg2 U, format string, args ...any) error
	New(arg1 T, arg2 U, messages ...string) error
	Wrapf(err error, arg1 T, arg2 U, format string, args ...any) error
	Wrap(err error, arg1 T, arg2 U, messages ...string) error
}

var _ tag2Builder[any, any] = Tag2[any, any]("")
