package main

import (
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/copperexchange/knox-primitives/pkg/core/curves/bls12381"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/edwards25519"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/k256"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/core/protocols"
	"github.com/copperexchange/knox-primitives/pkg/datastructures/hashset"
	bls_trusted_dealer "github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tbls/boldyreva02/keygen/trusted_dealer"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tecdsa/dkls23/keygen/trusted_dealer"
	lindell17_trusted_dealer "github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tecdsa/lindell17/keygen/trusted_dealer"
	frost_trusted_dealer "github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/frost/keygen/ed25519_trusted_dealer"
	lindell22_trusted_dealer "github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/lindell22/keygen/trusted_dealer"
)

var ConsoleGreen = "\033[32m"
var ConsoleReset = "\033[0m"
var supported = map[string][]string{
	"ecdsa": {protocols.DKLS23, protocols.LINDELL17},
	"eddsa": {protocols.FROST, protocols.LINDELL22},
	"bls":   {protocols.BLS},
}

func main() {
	keygenCmd.PersistentFlags().StringP("scheme", "s", "ecdsa", "signature scheme")
	keygenCmd.PersistentFlags().StringP("protocol", "p", protocols.DKLS23, "protocol used for key generation")
	keygenCmd.PersistentFlags().IntP("threshold", "t", 2, "threshold for key generation")
	keygenCmd.PersistentFlags().IntP("participants", "n", 3, "number of participants")

	if err := keygenCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

var keygenCmd = &cobra.Command{
	Use:   "keygen-cli",
	Short: "Generate private key, public key and print them to stdout",
	Long: `A command line tool to generate threshold private key shards, public key and print them to stdout.
Use flags to specify signature scheme, protocol, threshold and number of participants.
For example: ./keygen-cli -s ecdsa -p DKLs23 -t 2 -n 3`,
	Args: func(cmd *cobra.Command, args []string) error {
		scheme := cmd.Flag("scheme").Value.String()
		protocol := cmd.Flag("protocol").Value.String()
		threshold := cmd.Flag("threshold").Value.String()
		participants := cmd.Flag("participants").Value.String()
		var schemes []string
		if _, ok := supported[scheme]; ok {
			schemes = supported[scheme]
		}
		if _, ok := supported[scheme]; !ok {
			return errs.NewFailed("unsupported scheme: %s. Please use one of the following: %v", scheme, schemes)
		}
		selectedScheme := supported[scheme]
		if !contains(selectedScheme, protocol) {
			return errs.NewFailed("unsupported protocol: %s. Please use one of the following: %v", protocol, selectedScheme)
		}
		if threshold == "" {
			return errs.NewFailed("threshold is required")
		}
		t, err := strconv.Atoi(threshold)
		if err != nil {
			return errs.NewFailed("threshold must be an integer")
		}
		if t < 2 {
			return errs.NewFailed("threshold must be greater than 1")
		}
		if participants == "" {
			return errs.NewFailed("number of participants is required")
		}
		n, err := strconv.Atoi(participants)
		if err != nil {
			return errs.NewFailed("number of participants must be an integer")
		}
		if n < 2 {
			return errs.NewFailed("number of participants must be greater than 1")
		}
		if t > n {
			return errs.NewFailed("threshold must be less than or equal to number of participants")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		log.Default().Printf(`Running with the following parameters:
scheme: ` + cmd.Flag("scheme").Value.String() + `
protocol: ` + cmd.Flag("protocol").Value.String() + `
threshold: ` + cmd.Flag("threshold").Value.String() + `
participants: ` + cmd.Flag("participants").Value.String() + "\n\n")

		scheme := cmd.Flag("scheme").Value.String()
		protocol := cmd.Flag("protocol").Value.String()
		t, _ := strconv.Atoi(cmd.Flag("threshold").Value.String())
		n, _ := strconv.Atoi(cmd.Flag("participants").Value.String())

		var err error
		switch scheme {
		case "ecdsa":
			switch protocol {
			case protocols.DKLS23:
				err = dkls23(t, n)
			case protocols.LINDELL17:
				err = lindell17(t, n)
			}
		case "eddsa":
			switch protocol {
			case protocols.FROST:
				err = frost(t, n)
			case protocols.LINDELL22:
				err = lindell22(t, n)
			}
		case "bls":
			if protocol != protocols.BLS {
				err = errs.NewFailed("unsupported protocol: %s. Please use %s", protocol, protocols.BLS)
			} else {
				err = bls(t, n)
			}
		}
		if err != nil {
			log.Default().Println(err)
		}
	},
}

func lindell22(t, n int) error {
	cipherSuite := &integration.CipherSuite{
		Curve: edwards25519.New(),
		Hash:  sha512.New,
	}
	identities, err := test_utils.MakeIdentities(cipherSuite, n)
	if err != nil {
		return errs.WrapFailed(err, "could not generate identities")
	}
	cohortConfig := &integration.CohortConfig{
		CipherSuite:  cipherSuite,
		Participants: hashset.NewHashSet(identities),
		Protocol: &integration.ProtocolConfig{
			Name:                 protocols.LINDELL22,
			Threshold:            t,
			TotalParties:         n,
			SignatureAggregators: hashset.NewHashSet(identities),
		},
	}
	shards, err := lindell22_trusted_dealer.Keygen(cohortConfig, crand.Reader)
	if err != nil {
		return errs.WrapFailed(err, "could not generate private key shards")
	}
	log.Default().Printf("Public key: %s%x%s\n", ConsoleGreen, shards[identities[0].Hash()].PublicKeyShares.PublicKey.ToAffineCompressed(), ConsoleReset)

	i := 0
	for _, shard := range shards {
		i++
		log.Default().Printf("Private key shard #%d: %s%x%s\n", i, ConsoleGreen, shard.SigningKeyShare.Share.Bytes(), ConsoleReset)
	}
	return nil
}

func frost(t, n int) error {
	cipherSuite := &integration.CipherSuite{
		Curve: edwards25519.New(),
		Hash:  sha512.New,
	}
	identities, err := test_utils.MakeIdentities(cipherSuite, n)
	if err != nil {
		return errs.WrapFailed(err, "could not generate identities")
	}
	cohortConfig := &integration.CohortConfig{
		CipherSuite:  cipherSuite,
		Participants: hashset.NewHashSet(identities),
		Protocol: &integration.ProtocolConfig{
			Name:                 protocols.FROST,
			Threshold:            t,
			TotalParties:         n,
			SignatureAggregators: hashset.NewHashSet(identities),
		},
	}
	shards, err := frost_trusted_dealer.Keygen(cohortConfig, crand.Reader)
	if err != nil {
		return errs.WrapFailed(err, "could not generate private key shards")
	}
	log.Default().Printf("Public key: %s%x%s\n", ConsoleGreen, shards[identities[0].Hash()].PublicKey.ToAffineCompressed(), ConsoleReset)

	i := 0
	for _, shard := range shards {
		i++
		log.Default().Printf("Private key shard #%d: %s%x%s\n", i, ConsoleGreen, shard.Share.Bytes(), ConsoleReset)
	}
	return nil
}

func lindell17(t, n int) error {
	cipherSuite := &integration.CipherSuite{
		Curve: k256.New(),
		Hash:  sha256.New,
	}
	identities, err := test_utils.MakeIdentities(cipherSuite, n)
	if err != nil {
		return errs.WrapFailed(err, "could not generate identities")
	}
	cohortConfig := &integration.CohortConfig{
		CipherSuite:  cipherSuite,
		Participants: hashset.NewHashSet(identities),
		Protocol: &integration.ProtocolConfig{
			Name:                 protocols.LINDELL17,
			Threshold:            t,
			TotalParties:         n,
			SignatureAggregators: hashset.NewHashSet(identities),
		},
	}
	shards, err := lindell17_trusted_dealer.Keygen(cohortConfig, crand.Reader)
	if err != nil {
		return errs.WrapFailed(err, "could not generate private key shards")
	}
	log.Default().Printf("Public key: %s%x%s\n", ConsoleGreen, shards[identities[0].Hash()].SigningKeyShare.PublicKey.ToAffineCompressed(), ConsoleReset)

	i := 0
	for _, shard := range shards {
		i++
		log.Default().Printf("Private key shard #%d: %s%x%s\n", i, ConsoleGreen, shard.SigningKeyShare.Share.Bytes(), ConsoleReset)
	}
	return nil
}

func bls(t, n int) error {
	pointInK := new(bls12381.PointG1)
	cipherSuite := &integration.CipherSuite{
		Curve: pointInK.Curve(),
		Hash:  sha256.New,
	}
	identities, err := test_utils.MakeIdentities(cipherSuite, n)
	if err != nil {
		return errs.WrapFailed(err, "could not generate identities")
	}
	cohortConfig := &integration.CohortConfig{
		CipherSuite:  cipherSuite,
		Participants: hashset.NewHashSet(identities),
		Protocol: &integration.ProtocolConfig{
			Name:                 protocols.BLS,
			Threshold:            t,
			TotalParties:         n,
			SignatureAggregators: hashset.NewHashSet(identities),
		},
	}
	shards, err := bls_trusted_dealer.Keygen[*bls12381.PointG1](cohortConfig, crand.Reader)
	if err != nil {
		return errs.WrapFailed(err, "could not generate private key shards")
	}
	log.Default().Printf("Public key: %s%x%s\n", ConsoleGreen, shards[identities[0].Hash()].SigningKeyShare.PublicKey.Y.ToAffineCompressed(), ConsoleReset)

	i := 0
	for _, shard := range shards {
		i++
		log.Default().Printf("Private key shard #%d: %s%x%s\n", i, ConsoleGreen, shard.SigningKeyShare.Share.Bytes(), ConsoleReset)
	}
	return nil
}

func dkls23(t, n int) error {
	cipherSuite := &integration.CipherSuite{
		Curve: k256.New(),
		Hash:  sha256.New,
	}
	identities, err := test_utils.MakeIdentities(cipherSuite, n)
	if err != nil {
		return errs.WrapFailed(err, "could not generate identities")
	}
	cohortConfig := &integration.CohortConfig{
		CipherSuite:  cipherSuite,
		Participants: hashset.NewHashSet(identities),
		Protocol: &integration.ProtocolConfig{
			Name:                 protocols.DKLS23,
			Threshold:            t,
			TotalParties:         n,
			SignatureAggregators: hashset.NewHashSet(identities),
		},
	}

	shards, err := trusted_dealer.Keygen(cohortConfig, crand.Reader)
	if err != nil {
		return errs.WrapFailed(err, "could not generate private key shards")
	}
	log.Default().Printf("Public key: %s%x%s\n", ConsoleGreen, shards[identities[0].Hash()].SigningKeyShare.PublicKey.ToAffineCompressed(), ConsoleReset)

	i := 0
	for _, shard := range shards {
		i++
		log.Default().Printf("Private key shard #%d: %s%x%s\n", i, ConsoleGreen, shard.SigningKeyShare.Share.Bytes(), ConsoleReset)
	}
	return nil
}

func contains(scheme []string, protocol string) bool {
	for _, v := range scheme {
		if v == protocol {
			return true
		}
	}
	return false
}
