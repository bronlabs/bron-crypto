package errs2

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
)

type Tag string

type TraceableError interface {
	error
	Unwrap() error
	StackTrace() StackTrace
}

type TaggedError interface {
	error
	Tags() []Tag
	TagValue(tag Tag) (string, bool)
}

var (
	Unwrap = errors.Unwrap
	Is     = errors.Is
	As     = errors.As
	Join   = errors.Join
)

func New(format string, args ...any) error {
	if format == "" {
		return nil
	}
	return &errorWithStack{
		v:     fmt.Errorf(format, args...),
		stack: callers(),
	}
}

func WrapWithMessage(err error, format string, args ...any) error {
	if err == nil {
		return nil
	}
	return &errorWithStack{
		v:       err,
		stack:   callers(),
		context: fmt.Sprintf(format, args...),
	}
}

func Wrap(err error) error {
	if err == nil {
		return nil
	}
	return &errorWithStack{
		v:     err,
		stack: callers(),
	}
}

func AttachTag(err error, tag Tag, format string, args ...any) error {
	if err == nil {
		return nil
	}
	if alreadyTaggedErr, ok := err.(*taggedError); ok {
		alreadyTaggedErr.t[tag] = fmt.Sprintf(format, args...)
		return alreadyTaggedErr
	}
	if unwrappedErrorWithStack, ok := err.(*errorWithStack); ok {
		return &taggedError{
			errorWithStack: unwrappedErrorWithStack,
			t:              map[Tag]string{tag: fmt.Sprintf(format, args...)},
		}
	}
	return &taggedError{
		errorWithStack: New(err.Error(), nil).(*errorWithStack),
		t:              map[Tag]string{tag: fmt.Sprintf(format, args...)},
	}
}

func HasTag(err error, tag Tag) (string, bool) {
	for err != nil {
		if te, ok := err.(TaggedError); ok {
			if v, found := te.TagValue(tag); found {
				return v, true
			}
		}
		err = Unwrap(err)
	}
	return "", false
}

func StackTraces(err error) CombinedStackTrace {
	var traces []StackTrace
	for err != nil {
		if wst, ok := err.(TraceableError); ok {
			traces = append(traces, wst.StackTrace())
		}
		err = Unwrap(err)
	}
	return traces
}

func Must(f func() error) {
	if err := f(); err != nil {
		panic(err)
	}
}

func Must1[T any](f func() (T, error)) T {
	v, err := f()
	if err != nil {
		panic(err)
	}
	return v
}

func Must2[T1, T2 any](f func() (T1, T2, error)) (T1, T2) {
	v1, v2, err := f()
	if err != nil {
		panic(err)
	}
	return v1, v2
}

type errorWithStack struct {
	v       error
	stack   Stack
	context string
}

func (e *errorWithStack) Error() string {
	if e.context == "" {
		return e.v.Error()
	}
	return fmt.Sprintf("%s (%s)", e.v.Error(), e.context)
}

func (e *errorWithStack) Context() string {
	return e.context
}

func (e *errorWithStack) Unwrap() error {
	return e.v
}

func (e *errorWithStack) StackTrace() StackTrace {
	return e.stack.StackTrace()
}

func (e *errorWithStack) Format(s fmt.State, verb rune) {
	switch verb {
	case 'v':
		if s.Flag('+') {
			formatErrorChain(s, e)
			return
		}
		fallthrough
	case 's':
		if _, err := io.WriteString(s, e.Error()); err != nil {
			panic(err)
		}
	case 'q':
		fmt.Fprintf(s, "%q", e.Error())
	}
}

type taggedError struct {
	*errorWithStack
	t map[Tag]string
}

func (e *taggedError) Error() string {
	return e.errorWithStack.Error()
}

func (e *taggedError) Unwrap() error {
	return e.errorWithStack
}

func (e *taggedError) Tags() []Tag {
	return slices.Collect(maps.Keys(e.t))
}

func (e *taggedError) TagValue(tag Tag) (string, bool) {
	v, ok := e.t[tag]
	return v, ok
}

func (e *taggedError) Format(s fmt.State, verb rune) {
	switch verb {
	case 'v':
		if s.Flag('+') {
			formatErrorChain(s, e)
			return
		}
		fallthrough
	case 's':
		// Base message
		if _, err := io.WriteString(s, e.Error()); err != nil {
			panic(err)
		}
		// Inline tags, single line
		if len(e.t) > 0 {
			if _, err := io.WriteString(s, " ["); err != nil {
				panic(err)
			}
			first := true
			for k, v := range e.t {
				if !first {
					if _, err := io.WriteString(s, ", "); err != nil {
						panic(err)
					}
				}
				first = false
				fmt.Fprintf(s, "%s=%s", k, v)
			}
			if _, err := io.WriteString(s, "]"); err != nil {
				panic(err)
			}
		}
	case 'q':
		fmt.Fprintf(s, "%q", e.Error())
	}
}

func formatErrorChain(s fmt.State, err error) {
	idx := 0
	for err != nil {
		if idx > 0 {
			if _, _ = io.WriteString(s, "\n"); true {
			}
		}

		// Header for this error in the chain
		fmt.Fprintf(s, "err[%d]:\n %T: %s", idx, err, err.Error())

		// Tags, if any
		if te, ok := err.(TaggedError); ok {
			tags := te.Tags()
			if len(tags) > 0 {
				if _, errw := io.WriteString(s, "\n\tTags:"); errw != nil {
					panic(errw)
				}
				for _, tag := range tags {
					if val, ok := te.TagValue(tag); ok {
						fmt.Fprintf(s, " %s=%q", tag, val)
					}
				}
			}
		}

		// Stack trace, if available
		if wst, ok := err.(TraceableError); ok {
			st := wst.StackTrace()
			if len(st) > 0 {
				if _, errw := io.WriteString(s, "\n\tStack:"); errw != nil {
					panic(errw)
				}
				// StackTrace has its own %+v formatter; use that for detail
				fmt.Fprintf(s, "%+v", st)
			}
		}

		err = Unwrap(err)
		idx++
	}
}
