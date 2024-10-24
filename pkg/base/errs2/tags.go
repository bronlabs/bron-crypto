package errs2

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
)

var untaggedTag = NewTag0("", "")

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
	return tagMethodReturnType.PkgPath() == currentPkg
}

func IsTaggedWith(err error, tag Tagger) bool {
	return tag.IsTagging(err)
}

var _ Tagger = Tag0("")

type Tag0 string

func NewTag0(kind, description string) Tag0 {
	t := Tag0(kind)
	registerTag(t, description)
	return t
}

func (t0 Tag0) String() string {
	return strings.ReplaceAll(
		strings.ToUpper(string(t0)),
		" ", "_",
	)
}

func (t0 Tag0) Errorf(format string, args ...any) error {
	return tagged0Error{
		tag: t0,
		withStackError: withStackError{
			message: fmt.Sprintf(format, args...),
			stack:   callers(),
		},
	}
}

func (t0 Tag0) New(messages ...string) error {
	return t0.Errorf("%s", parseMessages(t0.String(), messages))
}

func (t0 Tag0) Wrapf(err error, format string, args ...any) error {
	return wrapped0Error{
		//nolint:errorlint,forcetypeassert // error package internals
		tagged0Error: t0.Errorf(format, args...).(tagged0Error),
		underlying:   err,
	}
}

func (t0 Tag0) Wrap(err error, messages ...string) error {
	return t0.Wrapf(err, "%s", parseMessages(t0.String(), messages))
}

//nolint:revive // TODO: export this?
func (t0 Tag0) With(keyValue map[string]any) tagged0WithKeyValueErrorBuilder {
	return tagged0WithKeyValueErrorBuilder{
		tag: t0,
		kv:  keyValue,
	}
}

func (t0 Tag0) IsTagging(err error) bool {
	//nolint:errorlint // error package internals
	if tErr, ok := err.(tagged0Error); ok {
		return tErr.tag == t0
	}
	//nolint:errorlint // error package internals
	if wrappedErr, ok := err.(wrapped0Error); ok {
		return t0.IsTagging(wrappedErr.tagged0Error)
	}
	//nolint:errorlint // error package internals
	if kvError, ok := err.(withKeyValueError); ok {
		return t0.IsTagging(kvError.error)
	}
	return false
}

var _ Tagger = Tag1[any]("")

type Tag1[T any] string

func NewTag1[T any](kind, description string) Tag1[T] {
	t := Tag1[T](kind)
	registerTag1(t, description)
	return t
}

func (t1 Tag1[T]) String() string {
	tName := typeName[T]()
	return fmt.Sprintf(
		"%s<%s>",
		strings.ReplaceAll(strings.ToUpper(string(t1)), " ", "_"),
		tName,
	)
}

func (t1 Tag1[T]) Errorf(arg T, format string, args ...any) error {
	return tagged1Error[T]{
		withStackError: withStackError{
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
	return wrapped1Error[T]{
		//nolint:errorlint,forcetypeassert // error package internals
		tagged1Error: t1.Errorf(arg, format, args...).(tagged1Error[T]),
		underlying:   err,
	}
}

func (t1 Tag1[T]) Wrap(err error, arg T, messages ...string) error {
	return t1.Wrapf(err, arg, parseMessages(t1.String(), messages))
}

//nolint:revive // TODO: export builder?
func (t1 Tag1[T]) With(keyValue map[string]any) tagged1WithKeyValueErrorBuilder[T] {
	return tagged1WithKeyValueErrorBuilder[T]{
		tag: t1,
		kv:  keyValue,
	}
}

func (t1 Tag1[T]) IsTagging(err error) bool {
	//nolint:errorlint // error package internals
	if tErr, ok := err.(tagged1Error[T]); ok {
		return tErr.tag == t1
	}
	//nolint:errorlint // error package internals
	if wrappedErr, ok := err.(wrapped1Error[T]); ok {
		return t1.IsTagging(wrappedErr.tagged1Error)
	}
	//nolint:errorlint // error package internals
	if kvError, ok := err.(withKeyValueError); ok {
		return t1.IsTagging(kvError.error)
	}
	return false
}

var _ Tagger = Tag2[any, any]("")

type Tag2[T, U any] string

func NewTag2[T, U any](kind, description string) Tag2[T, U] {
	t := Tag2[T, U](kind)
	registerTag2(t, description)
	return t
}

func (t2 Tag2[T, U]) New(arg1 T, arg2 U, messages ...string) error {
	return t2.Errorf(arg1, arg2, parseMessages(t2.String(), messages))
}

func (t2 Tag2[T, U]) Errorf(arg1 T, arg2 U, format string, args ...any) error {
	return tagged2Error[T, U]{
		withStackError: withStackError{
			message: fmt.Sprintf(format, args...),
			stack:   callers(),
		},
		tag:  t2,
		arg:  arg1,
		arg2: arg2,
	}
}

func (t2 Tag2[T, U]) String() string {
	tName := typeName[T]()
	uName := typeName[U]()
	return fmt.Sprintf(
		"%s<%s, %s>",
		strings.ReplaceAll(strings.ToUpper(string(t2)), " ", "_"),
		tName,
		uName,
	)
}

func (t2 Tag2[T, U]) Wrapf(err error, arg1 T, arg2 U, format string, args ...any) error {
	return wrapped2Error[T, U]{
		//nolint:errorlint,forcetypeassert // error package internals
		tagged2Error: t2.Errorf(arg1, arg2, format, args...).(tagged2Error[T, U]),
		underlying:   err,
	}
}

func (t2 Tag2[T, U]) Wrap(err error, arg1 T, arg2 U, messages ...string) error {
	return t2.Wrapf(err, arg1, arg2, parseMessages(t2.String(), messages))
}

//nolint:revive // TODO: export builder?
func (t2 Tag2[T, U]) With(keyValue map[string]any) tagged2WithKeyValueErrorBuilder[T, U] {
	return tagged2WithKeyValueErrorBuilder[T, U]{
		tag: t2,
		kv:  keyValue,
	}
}

func (t2 Tag2[T, U]) IsTagging(err error) bool {
	//nolint:errorlint // error package internals
	if tErr, ok := err.(tagged2Error[T, U]); ok {
		return tErr.tag == t2
	}
	//nolint:errorlint // error package internals
	if wrappedErr, ok := err.(wrapped2Error[T, U]); ok {
		return t2.IsTagging(wrappedErr.tagged2Error)
	}
	//nolint:errorlint // error package internals
	if kvError, ok := err.(withKeyValueError); ok {
		return t2.IsTagging(kvError.error)
	}
	return false
}

type tag0Builder interface {
	Errorf(format string, args ...any) error
	New(messages ...string) error
	Wrapf(err error, format string, args ...any) error
	Wrap(err error, messages ...string) error
}

var _ tag0Builder = Tag0("")

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

func typeName[T any]() string {
	typ := reflect.TypeOf((*T)(nil)).Elem()
	if typ.Kind() == reflect.Interface && typ.NumMethod() == 0 {
		return "any"
	} else {
		return typ.String()
	}
}
