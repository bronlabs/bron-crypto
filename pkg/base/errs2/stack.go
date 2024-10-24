package errs2

import (
	"fmt"
	"io"
	"path"
	"runtime"
	"strconv"
	"strings"
)

const UNKNOWN = "unknown"

// Frame represents a program counter inside a stack frame.
// For historical reasons if Frame is interpreted as a uintptr
// its value represents the program counter + 1.
type Frame uintptr

// pc returns the program counter for this frame;
// multiple frames may have the same PC value.
func (f Frame) pc() uintptr { return uintptr(f) - 1 }

// file returns the full path to the file that contains the
// function for this Frame's pc.
func (f Frame) file() string {
	fn := runtime.FuncForPC(f.pc())
	if fn == nil {
		return UNKNOWN
	}
	file, _ := fn.FileLine(f.pc())
	return file
}

// line returns the line number of source code of the
// function for this Frame's pc.
func (f Frame) line() int {
	fn := runtime.FuncForPC(f.pc())
	if fn == nil {
		return 0
	}
	_, line := fn.FileLine(f.pc())
	return line
}

// name returns the name of this function, if known.
func (f Frame) name() string {
	fn := runtime.FuncForPC(f.pc())
	if fn == nil {
		return UNKNOWN
	}
	return fn.Name()
}

// Format formats the frame according to the fmt.Formatter interface.
//
//	%s    source file
//	%d    source line
//	%n    function name
//	%v    equivalent to %s:%d
//
// Format accepts flags that alter the printing of some verbs, as follows:
//
//	%+s   function name and path of source file relative to the compile time
//	      GOPATH separated by \n\t (<funcname>\n\t<path>)
//	%+v   equivalent to %+s:%d
func (f Frame) Format(s fmt.State, verb rune) {
	switch verb {
	case 's':
		switch {
		case s.Flag('+'):
			if _, err := io.WriteString(s, f.name()); err != nil {
				panic(err)
			}
			if _, err := io.WriteString(s, "\n\t"); err != nil {
				panic(err)
			}
			if _, err := io.WriteString(s, f.file()); err != nil {
				panic(err)
			}
		default:
			if _, err := io.WriteString(s, path.Base(f.file())); err != nil {
				panic(err)
			}
		}
	case 'd':
		if _, err := io.WriteString(s, strconv.Itoa(f.line())); err != nil {
			panic(err)
		}
	case 'n':
		if _, err := io.WriteString(s, funcname(f.name())); err != nil {
			panic(err)
		}
	case 'v':
		f.Format(s, 's')
		if _, err := io.WriteString(s, ":"); err != nil {
			panic(err)
		}
		f.Format(s, 'd')
	}
}

// MarshalText formats a stacktrace Frame as a text string. The output is the
// same as that of fmt.Sprintf("%+v", f), but without newlines or tabs.
func (f Frame) MarshalText() ([]byte, error) {
	name := f.name()
	if name == UNKNOWN {
		return []byte(name), nil
	}
	return []byte(fmt.Sprintf("%s %s:%d", name, f.file(), f.line())), nil
}

// StackTrace is stack of Frames from innermost (newest) to outermost (oldest).
type StackTrace []Frame

// Format formats the stack of Frames according to the fmt.Formatter interface.
//
//	%s	lists source files for each Frame in the stack
//	%v	lists the source file and line number for each Frame in the stack
//
// Format accepts flags that alter the printing of some verbs, as follows:
//
//	%+v   Prints filename, function, and line number for each Frame in the stack.
func (st StackTrace) Format(s fmt.State, verb rune) {
	switch verb {
	case 'v':

		switch {
		case s.Flag('+'):
			for _, f := range st {
				if _, err := io.WriteString(s, "\n"); err != nil {
					panic(err)
				}
				f.Format(s, verb)
			}
		case s.Flag('#'):
			fmt.Fprintf(s, "%#v", []Frame(st))
		default:
			st.formatSlice(s, verb)
		}
	case 's':
		st.formatSlice(s, verb)
	}
}

// formatSlice will format this StackTrace into the given buffer as a slice of
// Frame, only valid when called with '%s' or '%v'.
func (st StackTrace) formatSlice(s fmt.State, verb rune) {
	if _, err := io.WriteString(s, "["); err != nil {
		panic(err)
	}
	for i, f := range st {
		if i > 0 {
			if _, err := io.WriteString(s, " "); err != nil {
				panic(err)
			}
		}
		f.Format(s, verb)
	}
	if _, err := io.WriteString(s, "]"); err != nil {
		panic(err)
	}
}

// Stack represents a Stack of program counters.
type Stack []uintptr

func (s *Stack) Format(st fmt.State, verb rune) {
	//nolint:gocritic,revive // keep switch
	switch verb {
	case 'v':
		//nolint:gocritic,revive // keep switch
		switch {
		case st.Flag('+'):
			for _, pc := range *s {
				f := Frame(pc)
				fmt.Fprintf(st, "\n%+v", f)
			}
		}
	}
}

func (s *Stack) StackTrace() StackTrace {
	f := make([]Frame, len(*s))
	for i := 0; i < len(f); i++ {
		f[i] = Frame((*s)[i])
	}
	return f
}

func callers() *Stack {
	const depth = 32
	var pcs [depth]uintptr
	n := runtime.Callers(3, pcs[:])
	var st Stack = pcs[0:n]
	return &st
}

// funcname removes the path prefix component of a function's name reported by func.Name().
func funcname(name string) string {
	i := strings.LastIndex(name, "/")
	name = name[i+1:]
	i = strings.Index(name, ".")
	return name[i+1:]
}
