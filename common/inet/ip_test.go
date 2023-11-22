package inet

import (
	"fmt"
	"net"
	"testing"
)

func TestIp2Int32(t *testing.T) {
	i := Ip2Int32(net.ParseIP("172.18.5.23").To4()) //386208428
	fmt.Println(i)
}
