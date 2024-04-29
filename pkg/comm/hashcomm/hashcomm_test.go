package hashcomm

import (
	"testing"
)

func TestHappyPath(t *testing.T) {
	hcs := HashCommitment{}
	commit, opening, err := hcs.Commit([]byte("00000001"), []byte("test"))
}
