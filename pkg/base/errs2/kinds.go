package errs2

import (
	"fmt"
	"reflect"
	"runtime"
	"slices"
	"strings"
)

const NoKind = Kind("")

func IsKinded(err error) bool {
	if err == nil {
		return false
	}
	t := reflect.TypeOf(err)
	method, exists := t.MethodByName("Kind")
	if !exists {
		return false
	}

	if method.Type.NumIn() != 1 {
		return false
	}

	kindMethodReturnType := method.Type.Out(0)
	currentPkg := runtime.FuncForPC(reflect.ValueOf(IsKinded).Pointer()).Name()
	currentPkg = currentPkg[:len(currentPkg)-len(".IsKinded")]
	return kindMethodReturnType.PkgPath() == currentPkg
}

func IsKindOf(err error, kinder Kinder) bool {
	return kinder.IsKinded(err)
}

var _ Kinder = Kind("")

type Kind string

func (k0 Kind) String() string {
	return strings.ReplaceAll(
		strings.ToUpper(string(k0)),
		" ", "_",
	)
}

func (k0 Kind) Errorf(format string, args ...any) error {
	return kindedError{
		kind: k0,
		withStackError: withStackError{
			message: fmt.Sprintf(format, args...),
			stack:   callers(),
		},
	}
}

func (k0 Kind) New(messages ...string) error {
	return k0.Errorf("%s", strings.Join(messages, " "))
}

func (k0 Kind) Wrapf(err error, format string, args ...any) error {
	return wrapped0Error{
		//nolint:errorlint,forcetypeassert // error package internals
		kindedError: k0.Errorf(format, args...).(kindedError),
		underlying:  err,
	}
}

func (k0 Kind) Wrap(err error, messages ...string) error {
	return k0.Wrapf(err, "%s", concat(k0.String(), messages...))
}

func (k0 Kind) IsKinded(err error) bool {
	//nolint:errorlint // error package internals
	if tErr, ok := err.(kindedError); ok {
		return tErr.kind == k0
	}
	//nolint:errorlint // error package internals
	if wrappedErr, ok := err.(wrapped0Error); ok {
		return k0.IsKinded(wrappedErr.kindedError)
	}

	return false
}

var _ Kinder = Kind1[any]("")

type Kind1[T any] string

func (k1 Kind1[T]) String() string {
	tName := typeName[T]()
	return fmt.Sprintf(
		"%s<%s>",
		strings.ReplaceAll(strings.ToUpper(string(k1)), " ", "_"),
		tName,
	)
}

func (k1 Kind1[T]) Errorf(arg T, format string, args ...any) error {
	return kinded1Error[T]{
		withStackError: withStackError{
			message: fmt.Sprintf(format, args...),
			stack:   callers(),
		},
		kind: k1,
		arg:  arg,
	}
}

func (k1 Kind1[T]) New(arg T, messages ...string) error {
	return k1.Errorf(arg, strings.Join(messages, " "))
}

func (k1 Kind1[T]) Wrapf(err error, arg T, format string, args ...any) error {
	return wrapped1Error[T]{
		//nolint:errorlint,forcetypeassert // error package internals
		kinded1Error: k1.Errorf(arg, format, args...).(kinded1Error[T]),
		underlying:   err,
	}
}

func (k1 Kind1[T]) Wrap(err error, arg T, messages ...string) error {
	return k1.Wrapf(err, arg, concat(k1.String(), messages...))
}

func (k1 Kind1[T]) IsKinded(err error) bool {
	//nolint:errorlint // error package internals
	if tErr, ok := err.(kinded1Error[T]); ok {
		return tErr.kind == k1
	}
	//nolint:errorlint // error package internals
	if wrappedErr, ok := err.(wrapped1Error[T]); ok {
		return k1.IsKinded(wrappedErr.kinded1Error)
	}

	return false
}

var _ Kinder = Kind2[any, any]("")

type Kind2[T, U any] string

func (k2 Kind2[T, U]) New(arg1 T, arg2 U, messages ...string) error {
	return k2.Errorf(arg1, arg2, strings.Join(messages, " "))
}

func (k2 Kind2[T, U]) Errorf(arg1 T, arg2 U, format string, args ...any) error {
	return kinded2Error[T, U]{
		withStackError: withStackError{
			message: fmt.Sprintf(format, args...),
			stack:   callers(),
		},
		kind: k2,
		arg:  arg1,
		arg2: arg2,
	}
}

func (k2 Kind2[T, U]) String() string {
	tName := typeName[T]()
	uName := typeName[U]()
	return fmt.Sprintf(
		"%s<%s, %s>",
		strings.ReplaceAll(strings.ToUpper(string(k2)), " ", "_"),
		tName,
		uName,
	)
}

func (k2 Kind2[T, U]) Wrapf(err error, arg1 T, arg2 U, format string, args ...any) error {
	return wrapped2Error[T, U]{
		//nolint:errorlint,forcetypeassert // error package internals
		kinded2Error: k2.Errorf(arg1, arg2, format, args...).(kinded2Error[T, U]),
		underlying:   err,
	}
}

func (k2 Kind2[T, U]) Wrap(err error, arg1 T, arg2 U, messages ...string) error {
	return k2.Wrapf(err, arg1, arg2, concat(k2.String(), messages...))
}

func (k2 Kind2[T, U]) IsKinded(err error) bool {
	//nolint:errorlint // error package internals
	if tErr, ok := err.(kinded2Error[T, U]); ok {
		return tErr.kind == k2
	}
	//nolint:errorlint // error package internals
	if wrappedErr, ok := err.(wrapped2Error[T, U]); ok {
		return k2.IsKinded(wrappedErr.kinded2Error)
	}

	return false
}

type kindedErrorBuilder interface {
	Errorf(format string, args ...any) error
	New(messages ...string) error
	Wrapf(err error, format string, args ...any) error
	Wrap(err error, messages ...string) error
}

var _ kindedErrorBuilder = Kind("")

type kinded1ErrorBuilder[T any] interface {
	Errorf(arg T, format string, args ...any) error
	New(arg T, messages ...string) error
	Wrapf(err error, arg T, format string, args ...any) error
	Wrap(err error, arg T, messages ...string) error
}

var _ kinded1ErrorBuilder[any] = Kind1[any]("")

type kinded2ErrorBuilder[T, U any] interface {
	Errorf(arg1 T, arg2 U, format string, args ...any) error
	New(arg1 T, arg2 U, messages ...string) error
	Wrapf(err error, arg1 T, arg2 U, format string, args ...any) error
	Wrap(err error, arg1 T, arg2 U, messages ...string) error
}

var _ kinded2ErrorBuilder[any, any] = Kind2[any, any]("")

func typeName[T any]() string {
	typ := reflect.TypeOf((*T)(nil)).Elem()
	if typ.Kind() == reflect.Interface && typ.NumMethod() == 0 {
		return "any"
	} else {
		return typ.String()
	}
}

func concat(car string, cdr ...string) string {
	return strings.Join(slices.Concat([]string{car}, cdr), " ")
}
