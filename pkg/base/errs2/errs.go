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

type ContextualError interface {
	error
	Context() string
}

var (
	Unwrap = errors.Unwrap
	Is     = errors.Is
	As     = errors.As
	Join   = errors.Join
)

func New(format string, args ...any) *Error {
	if format == "" {
		return nil
	}
	return &Error{
		v: fmt.Errorf(format, args...),
	}
}

func AttachStackTrace(err error) *Error {
	if err == nil {
		return nil
	}
	if er, ok := err.(*Error); ok {
		return er.WithStackTrace()
	}
	return &Error{
		v:     err,
		stack: callers(),
	}
}

func AttachMessage(err error, format string, args ...any) *Error {
	if err == nil {
		return nil
	}
	if er, ok := err.(*Error); ok {
		return er.WithMessage(format, args...)
	}
	return &Error{
		v:       err,
		context: fmt.Sprintf(format, args...),
	}
}

func AttachTag(err error, tag Tag, value string) *Error {
	if err == nil {
		return nil
	}
	if er, ok := err.(*Error); ok {
		return er.WithTag(tag, value)
	}
	return &Error{
		v: err,
		t: map[Tag]string{
			tag: value,
		},
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

type Error struct {
	v       error
	stack   Stack
	context string
	t       map[Tag]string
}

func (e *Error) Error() string {
	return e.v.Error()
	// if e.context == "" {
	// 	return e.v.Error()
	// }
	// return fmt.Sprintf("%s (%s)", e.v.Error(), e.context)
}

func (e *Error) Context() string {
	return e.context
}

func (e *Error) Unwrap() error {
	return e.v
}

func (e *Error) StackTrace() StackTrace {
	return e.stack.StackTrace()
}

func (e *Error) Format(s fmt.State, verb rune) {
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

		if len(e.context) > 0 {
			if _, err := io.WriteString(s, " ("); err != nil {
				panic(err)
			}
			if _, err := io.WriteString(s, e.context); err != nil {
				panic(err)
			}
			if _, err := io.WriteString(s, ")"); err != nil {
				panic(err)
			}
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

func (e *Error) WithStackTrace() *Error {
	return &Error{
		v:       e,
		stack:   callers(),
		context: e.context,
		t:       maps.Clone(e.t),
	}
}

func (e *Error) WithMessage(format string, args ...any) *Error {
	return &Error{
		v:       e,
		stack:   e.stack,
		context: fmt.Sprintf(format, args...),
		t:       maps.Clone(e.t),
	}
}

func (e *Error) WithTag(tag Tag, value string) *Error {
	out := &Error{
		v:       e,
		stack:   e.stack,
		context: e.context,
		t:       maps.Clone(e.t),
	}
	if out.t == nil {
		out.t = make(map[Tag]string)
	}
	out.t[tag] = value
	return out
}

func (e *Error) Tags() []Tag {
	return slices.Collect(maps.Keys(e.t))
}

func (e *Error) TagValue(tag Tag) (string, bool) {
	v, ok := e.t[tag]
	return v, ok
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
