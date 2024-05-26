package kuiper

import (
	"fmt"
	"reflect"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
)

type SourceSubGroups interface {
	Pluto | Triton
}

func GetSourceSubGroup[S SourceSubGroups]() curves.Curve {
	s := new(S)
	name := reflect.TypeOf(s).Elem().Name()
	switch name {
	case "Pluto":
		return NewPluto()
	case "Triton":
		return NewTriton()
	default:
		panic(fmt.Sprintf("name %s is not supported", name))
	}
}
