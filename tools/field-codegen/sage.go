package main

import (
	"bytes"
	"context"
	_ "embed"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"math/big"
	"strings"
)

//go:embed root-of-unity.sage.py
var sageScriptString string

func ComputeRootOfUnity(modulusStr string) (rootOfUnity *big.Int, modulus *big.Int) {
	sageOutputBuffer := bytes.NewBuffer(nil)

	sageMathRequest := testcontainers.ContainerRequest{
		Image: "sagemath/sagemath",
		Files: []testcontainers.ContainerFile{
			{Reader: bytes.NewBufferString(sageScriptString), ContainerFilePath: "/tmp/script.sage.py", FileMode: 0x755},
		},
		Cmd: []string{"/tmp/script.sage.py", "'" + modulusStr + "'"},
		LogConsumerCfg: &testcontainers.LogConsumerConfig{
			Consumers: []testcontainers.LogConsumer{NewWriterLogConsumer(sageOutputBuffer)},
		},
		WaitingFor: wait.ForExit(),
	}

	sageMathContainer := Must(testcontainers.GenericContainer(context.Background(), testcontainers.GenericContainerRequest{
		ContainerRequest: sageMathRequest,
		Started:          true,
	}))
	defer sageMathContainer.Terminate(context.Background())

	out := strings.Split(sageOutputBuffer.String(), " ")
	rootOfUnity = MustOk(new(big.Int).SetString(strings.TrimSpace(out[0]), 0))
	modulus = MustOk(new(big.Int).SetString(strings.TrimSpace(out[1]), 0))

	return rootOfUnity, modulus
}
