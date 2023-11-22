package inet

import (
	"fmt"
	"testing"
)

func TestConvertToBytesPerSecond(t *testing.T) {
	testCases := []struct {
		input       string
		expected    int
		expectError bool
	}{
		{"100KB/s", 100 * 1000, false},
		{"100kb/s", 100 * 1000, false},
		{"100MB/s", 100 * 1000 * 1000, false},
		{"100mb/s", 100 * 1000 * 1000, false},
		{"invalid", 0, true},
		{"123", 0, true},
	}

	for _, tc := range testCases {
		result, err := BytesPerSecond2Int(tc.input)

		fmt.Println(result, err)
	}
}
