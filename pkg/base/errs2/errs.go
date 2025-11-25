package errs2

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strconv"
)

const (
	errorHeader       = "ERROR: "
	defaultIndent     = "  "
	tagsPrefix        = "--- Tags: "
	stackFramePrefix  = "--- Frame: "
	sentinelSeparator = ": "
)

var (
	Unwrap = errors.Unwrap
	Is     = errors.Is
	As     = errors.As
)

type CryptoError interface {
	error
	fmt.Formatter

	WithTag(string, any) CryptoError
	WithMessage(format string, args ...any) CryptoError
	WithStackFrame() CryptoError
	Tags() map[string]any
	StackFrame() *StackFrame
}

func New(format string, args ...any) CryptoError {
	return &sentinelError{
		message: fmt.Sprintf(format, args...),
	}
}

func Join(errs ...error) CryptoError {
	if len(errs) == 0 {
		return nil
	}
	pc, _, _, _ := runtime.Caller(1)
	var children []error
	for _, e := range errs {
		sentinelErr := &sentinelError{}
		if errors.As(e, &sentinelErr) {
			children = append(children, &errorImpl{
				message:    sentinelErr.message,
				wrapped:    []error{sentinelErr},
				stackFrame: nil,
				tags:       nil,
			})
		} else {
			children = append(children, e)
		}
	}

	return &errorImpl{
		message:    "",
		wrapped:    errs,
		stackFrame: NewStackFrame(pc),
		tags:       nil,
	}
}

func Wrap(err error) CryptoError {
	pc, _, _, _ := runtime.Caller(1)

	sentinelErr := &sentinelError{}
	if errors.As(err, &sentinelErr) {
		return &errorImpl{
			message:    sentinelErr.message,
			wrapped:    []error{sentinelErr},
			stackFrame: NewStackFrame(pc),
			tags:       nil,
		}
	} else {
		return &errorImpl{
			message:    "",
			wrapped:    []error{err},
			stackFrame: NewStackFrame(pc),
			tags:       nil,
		}
	}
}

func HasTag(err error, tag string) (any, bool) {
	var taggedErr hasTags
	if errors.As(err, &taggedErr) {
		v, ok := taggedErr.Tags()[tag]
		return v, ok
	}

	return nil, false
}

type sentinelError struct {
	message string
}

func (e *sentinelError) WithTag(s string, a any) CryptoError {
	pc, _, _, _ := runtime.Caller(1)
	return &errorImpl{
		message:    e.message,
		wrapped:    []error{e},
		stackFrame: NewStackFrame(pc),
		tags:       map[string]any{s: a},
	}
}

func (e *sentinelError) WithMessage(format string, args ...any) CryptoError {
	pc, _, _, _ := runtime.Caller(1)
	return &errorImpl{
		message:    e.message + sentinelSeparator + fmt.Sprintf(format, args...),
		wrapped:    []error{e},
		stackFrame: NewStackFrame(pc),
		tags:       nil,
	}
}

func (e *sentinelError) WithStackFrame() CryptoError {
	pc, _, _, _ := runtime.Caller(0)
	return &errorImpl{
		message:    e.message,
		wrapped:    []error{e},
		stackFrame: NewStackFrame(pc),
		tags:       nil,
	}
}

func (e *sentinelError) Error() string {
	return e.message
}

func (e *sentinelError) Format(s fmt.State, verb rune) {
	switch verb {
	case 'v', 's', 'q':
		_, _ = fmt.Fprintf(s, "%s%s\n", errorHeader, e.Error())
	}
}

func (e *sentinelError) Tags() map[string]any {
	return nil
}

func (e *sentinelError) StackFrame() *StackFrame {
	return nil
}

type errorImpl struct {
	message    string
	wrapped    []error
	stackFrame *StackFrame
	tags       map[string]any
}

func (e *errorImpl) WithTag(s string, a any) CryptoError {
	if e.tags == nil {
		e.tags = map[string]any{s: a}
	} else {
		e.tags[s] = a
	}
	return e
}

func (e *errorImpl) WithMessage(format string, args ...any) CryptoError {
	if e.message == "" {
		e.message = fmt.Sprintf(format, args...)
	} else {
		e.message = e.message + sentinelSeparator + fmt.Sprintf(format, args...)
	}
	return e
}

func (e *errorImpl) WithStackFrame() CryptoError {
	pc, _, _, _ := runtime.Caller(1)
	e.stackFrame = NewStackFrame(pc)
	return e
}

func (e *errorImpl) Error() string {
	return e.message
}

func (e *errorImpl) Unwrap() []error {
	return e.wrapped
}

func (e *errorImpl) StackFrame() *StackFrame {
	return e.stackFrame
}

func (e *errorImpl) Tags() map[string]any {
	return e.tags
}

func (e *errorImpl) Format(s fmt.State, verb rune) {
	switch verb {
	case 'v':
		if s.Flag('+') {
			buf := new(bytes.Buffer)
			formatErrorChainDetailed(buf, errorHeader, "", e)
			_, _ = s.Write(buf.Bytes())
			break
		}
		fallthrough
	case 's':
		_, _ = io.WriteString(s, errorHeader+e.Error()+"\n")
		if len(e.Tags()) > 0 {
			tags, err := json.Marshal(e.Tags())
			if err == nil {
				_, _ = io.WriteString(s, tagsPrefix)
				_, _ = io.WriteString(s, string(tags))
				_, _ = io.WriteString(s, "\n")
			}
		}
	case 'q':
		_, _ = fmt.Fprintf(s, "%s%s\n", errorHeader, e.Error())
	}
}

type hasTags interface {
	error
	Tags() map[string]any
}

type hasStackFrame interface {
	error
	StackFrame() *StackFrame
}

type wrapsError interface {
	error
	Unwrap() error
}

type wrapsMultipleErrors interface {
	error
	Unwrap() []error
}

func formatErrorChainDetailed(buffer *bytes.Buffer, header, indent string, err error) {
	buffer.WriteString(indent)
	buffer.WriteString(header)
	buffer.WriteString(err.Error())
	buffer.WriteString("\n")
	var stackFrameErr hasStackFrame
	if errors.As(err, &stackFrameErr) {
		stackFrame := stackFrameErr.StackFrame()
		buffer.WriteString(indent)
		buffer.WriteString(stackFramePrefix)
		buffer.WriteString(stackFrame.File + ":" + strconv.Itoa(stackFrame.LineNo))
		buffer.WriteString("\n")
	}
	var tagsErr hasTags
	if errors.As(err, &tagsErr) {
		tags := tagsErr.Tags()
		tagsStr, err := json.Marshal(tags)
		if err == nil {
			buffer.WriteString(indent)
			buffer.WriteString(tagsPrefix)
			buffer.Write(tagsStr)
			buffer.WriteString("\n")
		}
	}

	var children []error
	var joined wrapsMultipleErrors
	ok := errors.As(err, &joined)
	if ok {
		children = append(children, joined.Unwrap()...)
	}
	var wrapped wrapsError
	ok = errors.As(err, &wrapped)
	if ok {
		children = append(children, wrapped.Unwrap())
	}
	filteredChildren := nonSentinelErrorsFilter(children)
	if len(filteredChildren) > 0 {
		buffer.WriteString(indent)
		buffer.WriteString("Caused by:\n")
		for i, child := range filteredChildren {
			formatErrorChainDetailed(buffer, "["+strconv.Itoa(i)+"] ", indent+defaultIndent, child)
		}
	}
}

func nonSentinelErrorsFilter(errs []error) []error {
	var filtered []error
	for _, e := range errs {
		sentinelError := &sentinelError{}
		if errors.As(e, &sentinelError) {
			filtered = append(filtered, e)
		}
	}

	return filtered
}
