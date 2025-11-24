package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"text/template"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

//go:embed millerrabin.go.tmpl
var millerrabinTemplateString string

// computeMillerRabinIterations executes the fips1865c.sage script with the given
// statistical security bits parameter and returns a map of bit lengths to iteration counts.
func computeMillerRabinIterations(sageScriptPath string, statSecurityBits uint) (map[uint]int, error) {
	// Read the sage script
	sageScript, err := os.ReadFile(sageScriptPath)
	if err != nil {
		return nil, fmt.Errorf("read sage script: %w", err)
	}

	// Buffer to capture sage output
	outputBuffer := bytes.NewBuffer(nil)

	// Create container request
	sageMathRequest := testcontainers.ContainerRequest{
		Image: "sagemath/sagemath",
		Files: []testcontainers.ContainerFile{
			{
				Reader:            bytes.NewReader(sageScript),
				ContainerFilePath: "/tmp/fips1865c.sage",
				FileMode:          0755,
			},
		},
		Cmd: []string{"/tmp/fips1865c.sage", fmt.Sprintf("%d", statSecurityBits)},
		LogConsumerCfg: &testcontainers.LogConsumerConfig{
			Consumers: []testcontainers.LogConsumer{newWriterLogConsumer(outputBuffer)},
		},
		WaitingFor: wait.ForExit(),
	}

	// Start container
	sageMathContainer := must(testcontainers.GenericContainer(
		context.Background(),
		testcontainers.GenericContainerRequest{
			ContainerRequest: sageMathRequest,
			Started:          true,
		},
	))
	defer sageMathContainer.Terminate(context.Background())

	// Parse JSON output
	var result map[string]any
	if err := json.Unmarshal(outputBuffer.Bytes(), &result); err != nil {
		return nil, fmt.Errorf("parse sage JSON output: %w\nOutput was: %s", err, outputBuffer.String())
	}

	// Convert to map[uint]int
	iterations := make(map[uint]int)
	for key, value := range result {
		// Keys are bit lengths as strings
		var bitLen uint
		if _, err := fmt.Sscanf(key, "%d", &bitLen); err != nil {
			continue
		}
		// Values could be integers or floats, handle both
		switch v := value.(type) {
		case float64:
			iterations[bitLen] = int(v)
		case int:
			iterations[bitLen] = v
		}
	}

	return iterations, nil
}

// generateMillerRabinCode generates the millerrabin.gen.go file in the nt package
func generateMillerRabinCode(baseDir string, iterations map[uint]int) error {
	ntDir := filepath.Join(baseDir, "nt")
	outputFile := filepath.Join(ntDir, "millerrabin.gen.go")

	// Use embedded template
	tpl := must(template.New("millerrabin").Parse(millerrabinTemplateString))

	f := must(os.Create(outputFile))
	defer f.Close()

	if err := tpl.Execute(f, iterations); err != nil {
		return fmt.Errorf("execute template: %w", err)
	}

	return nil
}
