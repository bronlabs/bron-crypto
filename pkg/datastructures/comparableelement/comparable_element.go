package comparableelement

import (
	"strings"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
)

type ComparableElement interface {
	HashCode() string
}

func Compare(a ComparableElement, b ComparableElement) int {
	return strings.Compare(a.HashCode(), b.HashCode())
}

func Equals(a ComparableElement, b ComparableElement) bool {
	return Compare(a, b) == 0
}

// implement Bubble Sort for memory efficiency. Return error if there is duplicate element
func SortNoDuplicate(elements []ComparableElement) ([]ComparableElement, error) {
	var isDone = false

	for !isDone {
		isDone = true
		var i = 0
		for i < len(elements)-1 {
			if Compare(elements[i], elements[i+1]) == 0 {
				return nil, errs.NewDuplicate("duplicate element")
			}
			if Compare(elements[i], elements[i+1]) > 0 {
				elements[i], elements[i+1] = elements[i+1], elements[i]
				isDone = false
			}
			i++
		}
	}

	return elements, nil
}
