package scutclient_go

import (
	"errors"

	pcap "github.com/google/gopacket/pcap"

	// "log"
	"net"

	gopacket "github.com/google/gopacket"
	// "crypto/md5"
)

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
