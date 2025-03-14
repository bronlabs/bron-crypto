package mina_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorr/mina"
)

func Test_BitsToPackedFields(t *testing.T) {
	t.Parallel()
	input := new(mina.ROInput).Init()
	input.AddString("someveryverylongmessagecmrewiugriuhtrlugchmtrlugchslrifudjtrfunhvgudysrthvgnkyudrtgcvdnkurytcnhgkdtuyrnhgkryutcghksrecyuhgkstruhgmsrtucghslrutcghslrtuhgkdsfuhgcmsruthcvgslrtuhgmlrtuichslrmutsrthdl")
	fields := input.PackToFields()

	require.Len(t, fields, 7)
	require.Equal(t, "6739959678053839808442019806815009096953251624254956745969670397973851731662", fields[0].Nat().Big().Text(10))
	require.Equal(t, "11694274828623079122518667601523414095790905048332939675937030108127164021337", fields[1].Nat().Big().Text(10))
	require.Equal(t, "15109057306232126396170098590048975416355454488766875820599404248434383677153", fields[2].Nat().Big().Text(10))
	require.Equal(t, "19710143195313378682873744829237720688259603907450714948479184137717694444985", fields[3].Nat().Big().Text(10))
	require.Equal(t, "17227962557078458526949747460171157970072782053868244093602941461684486071830", fields[4].Nat().Big().Text(10))
	require.Equal(t, "25659442655828297319107427068349186374832281178012109346410085717571425458971", fields[5].Nat().Big().Text(10))
	require.Equal(t, "3721075549420", fields[6].Nat().Big().Text(10))
}
