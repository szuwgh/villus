package user

import (
	"encoding/binary"
	"log"
	"net"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type Ipv4KeyT struct {
	Pid   uint32
	Saddr uint32
	Daddr uint32
	Lport uint16
	Dport uint16
}

func AttachTcpKprobe() (err error) {
	fn := "tcp_sendmsg"

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	kp, err := link.Kprobe(fn, objs.KtcpSendmsg, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()

	// Read loop reporting the total amount of times the kernel
	// function was entered, once per second.
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	log.Println("Waiting for events..")
	log.Printf("%-15s %-6s -> %-15s %-6s %-6s",
		"Src addr",
		"Port",
		"Dest addr",
		"Port",
		"RTT",
	)
	for range ticker.C {
		var values []uint32
		var key Ipv4KeyT
		// if err := objs.KprobeMap.Lookup(mapKey, &value); err != nil {
		// 	log.Fatalf("reading map: %v", err)
		// }
		iter := objs.bpfMaps.TcpMap.Iterate()
		for iter.Next(&key, &values) {
			var sum uint32
			for _, n := range values {
				sum += n
			}
			log.Printf("%-15s %-6d -> %-15s %-6d %-6d",
				intToIP(key.Saddr),
				key.Lport,
				intToIP(key.Daddr),
				key.Dport,
				sum,
			)
		}
		//log.Printf("%s called %d times\n", fn, value)
	}
	return nil
}

// intToIP converts IPv4 number to net.IP
func intToIP(ipNum uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, ipNum)
	return ip
}
