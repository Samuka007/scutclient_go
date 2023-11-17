package scutclient_go

import (
	"errors"

	pcap "github.com/google/gopacket/pcap"

	// "log"
	"net"

	gopacket "github.com/google/gopacket"
	// "crypto/md5"
)

var ifcIndexCnt = 0

type IfcParse struct {
	index      int
	PcapName   string
	NetName    string
	PcapTarget *pcap.Interface
	NetTarget  *net.Interface
}

func getPossibleInterfaces() (map[string]IfcParse, error) {
	ifcs, _ := pcap.FindAllDevs()
	possible := map[string]IfcParse{}
	for _, ifc := range ifcs {
		for _, addr := range ifc.Addresses {
			if addr.IP.To4() != nil && !addr.IP.IsLoopback() {
				ifcIndexCnt++
				possible[addr.IP.String()] = IfcParse{
					index:      ifcIndexCnt,
					PcapName:   ifc.Name,
					NetName:    "",
					PcapTarget: &ifc,
				}
			}
		}
		// fmt.Println(ifc.Name, ifc.Description)
	}

	ifcs2, _ := net.Interfaces()
	for _, ifc := range ifcs2 {
		addrs, _ := ifc.Addrs()
		// only echo ipv4 addr
		for _, addr := range addrs {
			for ip, ifcParse := range possible {
				if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4().String() == ip {
					ifcParse.NetName = ifc.Name
					ifcParse.NetTarget = &ifc
					possible[ip] = ifcParse
				}
			}
		}
		// fmt.Println(ifc.Name, addrs)
	}
	return possible, nil
}

func listNetworkDev() ([]string, error) {
	interfaces, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}
	var ret []string
	for _, ifc := range interfaces {
		ret = append(ret, ifc.Description)
	}
	return ret, nil
}

func listNetworkAdapter() ([]string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var ret []string
	for _, ifc := range interfaces {
		ret = append(ret, ifc.Name)
	}
	return ret, nil
}

func SelectNetworkDev(dev string) (*pcap.Interface, error) {
	interfaces, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}
	for _, ifc := range interfaces {
		if ifc.Description == dev {
			return &ifc, nil
		}
	}
	return nil, errors.New("未发现硬件设备" + dev)
}

func SelectNetworkAdapter(adapter string) (net.HardwareAddr, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, ifc := range interfaces {
		if ifc.Name == adapter {
			return ifc.HardwareAddr, nil
		}
	}
	return nil, errors.New("无法获取对应网卡")
}

var fillbuf = []byte{}

var fillLayer = gopacket.Payload(fillbuf)
