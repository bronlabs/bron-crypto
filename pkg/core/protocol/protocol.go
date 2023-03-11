package protocol

type Protocol string

const (
	FROST = "FROST"
)

var Supported = map[Protocol]bool{FROST: true}
