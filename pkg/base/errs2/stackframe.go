package errs2

import (
	"runtime"
	"strings"
)

type StackFrame struct {
	File           string
	LineNo         int
	Name           string
	Package        string
	ProgramCounter uintptr
}

func NewStackFrame(pc uintptr) *StackFrame {
	fn := runtime.FuncForPC(pc)
	fnFileName, fnLineNo := fn.FileLine(pc)
	fnName := fn.Name()
	fnPkgName := ""
	if lastSlash := strings.LastIndex(fnName, "/"); lastSlash >= 0 {
		fnPkgName += fnName[:lastSlash] + "/"
		fnName = fnName[lastSlash+1:]
	}
	if period := strings.Index(fnName, "."); period >= 0 {
		fnPkgName += fnName[:period]
		fnName = fnName[period+1:]
	}

	fnName = strings.ReplaceAll(fnName, "·", ".")

	return &StackFrame{File: fnFileName, LineNo: fnLineNo, Name: fnName, Package: fnPkgName, ProgramCounter: pc}
}
