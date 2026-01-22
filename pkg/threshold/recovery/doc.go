// Package recovery provides protocol for reconstructing a missing party’s Feldman share as described in “Proactive Secret Sharing”. Parties collaboratively blind a fresh sharing, offset it to the missing index, and interpolate the blinded shares to restore the lost value.
//
// See README.md for details.
package recovery
