package utils

import (
	"encoding/hex"
	"fmt"
)

type strings struct{}

var Strings strings

// DecodeHex decodes a hex string into a byte slice. It panics if the string is not a valid hex string.
func (strings) DecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func (strings) TruncateWithEllipsis(text string, maxLen int) string {
	if len(text) > maxLen {
		return text[:maxLen] + fmt.Sprintf("...(%d)", len(text)-maxLen)
	}
	return text
}
