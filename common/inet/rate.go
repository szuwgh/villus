package inet

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const (
	Kbit = 1000
	Mbit = Kbit * 1000
	Gbit = Mbit * 1000
)

// 将 100KB/s 100 KB/s 转成 int
func BytesPerSecond2Int(rate string) (uint64, error) {
	re := regexp.MustCompile(`(\d+)\s*([kKmMgGtT][bB]/s)`)
	parts := re.FindStringSubmatch(rate)
	if parts == nil || len(parts) != 3 {

		return 0, fmt.Errorf("invalid rate format: %s", rate)
	}

	// 获取速率和单位
	valueStr := parts[1]
	unit := parts[2]

	// 将速率字符串转换为整数
	value, err := strconv.ParseUint(valueStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("error converting value to integer: %s", valueStr)
	}

	// 根据单位进行转换
	switch strings.ToUpper(unit) {
	case "KB/S":
		return value * 1000, nil
	case "MB/S":
		return value * 1000 * 1000, nil
	default:
		return 0, fmt.Errorf("unknown unit: %s", unit)
	}
}

func IntToToBytesPerSecond(rate uint64) string {

	switch {
	case rate >= Gbit:
		return fmt.Sprintf("%dGB/s", rate/Gbit)
	case rate >= Mbit:
		return fmt.Sprintf("%dGB/s", rate/Mbit)
	case rate >= Kbit:
		return fmt.Sprintf("%dKB/s", rate/Kbit)
	}
	return ""
}
