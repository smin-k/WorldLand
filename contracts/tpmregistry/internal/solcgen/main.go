package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

func main() {
	source, err := os.ReadFile("contract/registry.sol")
	check(err)
	input := map[string]interface{}{
		"language": "Solidity",
		"sources": map[string]interface{}{
			"registry.sol": map[string]string{"content": string(source)},
		},
		"settings": map[string]interface{}{
			"optimizer": map[string]interface{}{"enabled": true, "runs": 200},
			"outputSelection": map[string]interface{}{
				"*": map[string]interface{}{
					"*": []string{"abi", "evm.deployedBytecode.object", "storageLayout"},
				},
			},
		},
	}
	encodedInput, err := json.Marshal(input)
	check(err)
	executable := "npx"
	if runtime.GOOS == "windows" {
		executable = "npx.cmd"
	}
	command := exec.Command(executable, "--yes", "solc@0.8.17", "--standard-json")
	command.Stdin = bytes.NewReader(encodedInput)
	output, err := command.CombinedOutput()
	if err != nil {
		panic(fmt.Errorf("solc failed: %w\n%s", err, output))
	}
	jsonStart := bytes.IndexByte(output, '{')
	if jsonStart < 0 {
		panic(fmt.Errorf("solc returned no JSON: %s", output))
	}
	var result struct {
		Contracts map[string]map[string]struct {
			ABI json.RawMessage `json:"abi"`
			EVM struct {
				DeployedBytecode struct {
					Object string `json:"object"`
				} `json:"deployedBytecode"`
			} `json:"evm"`
			StorageLayout json.RawMessage `json:"storageLayout"`
		} `json:"contracts"`
		Errors []struct {
			Severity  string `json:"severity"`
			Formatted string `json:"formattedMessage"`
		} `json:"errors"`
	}
	check(json.Unmarshal(output[jsonStart:], &result))
	for _, compilerError := range result.Errors {
		if compilerError.Severity == "error" {
			panic(compilerError.Formatted)
		}
	}
	contract, ok := result.Contracts["registry.sol"]["TPMDIDRegistry"]
	if !ok || contract.EVM.DeployedBytecode.Object == "" {
		panic("TPMDIDRegistry compiler output missing")
	}
	prettyABI := prettyJSON(contract.ABI)
	prettyStorage := prettyJSON(contract.StorageLayout)
	check(os.WriteFile("contract/registry.abi.json", append(prettyABI, '\n'), 0o644))
	check(os.WriteFile("contract/registry.runtime.hex", []byte(contract.EVM.DeployedBytecode.Object+"\n"), 0o644))
	check(os.WriteFile("contract/registry.storage.json", append(prettyStorage, '\n'), 0o644))
}

func prettyJSON(input []byte) []byte {
	var output bytes.Buffer
	check(json.Indent(&output, input, "", "  "))
	return output.Bytes()
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
