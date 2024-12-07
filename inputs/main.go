package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"strings"
)

// HexToUint8Array converts a hex string to a comma-separated uint8 array string
func HexToUint8Array(hexStr string) (string, error) {
	// Clean the input string
	hexStr = strings.ReplaceAll(hexStr, " ", "")
	hexStr = strings.TrimPrefix(hexStr, "0x")

	// Ensure even length
	if len(hexStr)%2 != 0 {
		hexStr = "0" + hexStr
	}

	// Convert to bytes
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return "", err
	}

	// Convert bytes to comma-separated uint8 values
	var values []string
	for _, b := range bytes {
		values = append(values, fmt.Sprintf("%d", b))
	}

	return strings.Join(values, ", "), nil
}

func main() {
	// Example hex strings
	hexStrings := []string{
		"02000000000101f1d3b3c8ffa8bd29cd2ae5ff721ed5317c6f8211b8b6e923bba0fa36977261fd0100000000ffffffff02a0860100000000002200208ac829f2937b1f8277c3f41f5e1d1f6045ed6069eb67a07005194f6c50cfedecaeb81108000000001600144eef35b52820d180e090a55a6bf6e2951a6dd33d02473044022079724cd1b6815f1b459213061f17e34212142e5f9507d39750214a3191446f4e02205c78795995bdb2dee9f1d2ecfc0ba66784a06f6c1e1d749fed37f6692b0d9e90012103ddb9287f795f428ada8d7dd7be094e33893e84ca483e80d1cfe4119c970bbb7c00000000",
	}

	for _, hexStr := range hexStrings {
		result, err := HexToUint8Array(hexStr)
		if err != nil {
			log.Printf("Error converting %q: %v\n", hexStr, err)
			continue
		}

		fmt.Printf("Hex: %s\nUint8 Array: [%s]\n\n", hexStr, result)
	}
}
