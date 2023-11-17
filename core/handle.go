package scutclient_go

/*
	Device for ETH_EAP authentication
	Adapter for UDP authentication
*/

import (
	"bytes"
	"crypto/md5"
	"errors"
	"fmt"
	"net"

	gopacket "github.com/google/gopacket"
	layers "github.com/google/gopacket/layers"
	pcap "github.com/google/gopacket/pcap"
)

var (
	BroadcastAddr = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff} // 广播MAC地址
	MultiCastAddr = net.HardwareAddr{0x01, 0x80, 0xc2, 0x00, 0x00, 0x03} // 多播MAC地址
	UnicastAddr   = net.HardwareAddr{0x01, 0xd0, 0xf8, 0x00, 0x00, 0x03} // 单播MAC地址
)

// const ETH_FRAME_LEN = 1514
var (
	EthHeader = [...]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x8e}
	BroadcastHeader = [...]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0x88, 0x8e}
	MultcastHeader = [...]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0x88, 0x8e}
	UnicastHeader = [...]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0xd0, 0xf8, 0x00, 0x00, 0x03, 0x88, 0x8e}
)

var (
	DrcomServerAddr = net.IPv4(202, 38, 210, 131)
	DrcomDNS1Addr   = net.IPv4(222, 201, 130, 30)
	DrcomDNS2Addr   = net.IPv4(222, 201, 130, 33)
	DrcomServerPort = 61440
)

type DrcomInfo struct {
	ifc *IfcParse

	LocalIP      net.IP
	DrcomSvrAddr net.IP
	DrcomDNS1    net.IP
	DrcomDNS2    net.IP
	DrcomSvrPort int
}

func (info *DrcomInfo) String() string {
	return "==================================================\n" +
		"DrcomInfo: \n" +
		fmt.Sprintf("Device Name: %s", info.ifc.PcapName) +
		fmt.Sprintf("Device Mac: %s", info.getLocalMac().String()) +
		fmt.Sprintf("LocalIP: %s", info.LocalIP) +
		fmt.Sprintf("DrcomSvrAddr: %s", info.DrcomSvrAddr) +
		fmt.Sprintf("DrcomDNS1: %s", info.DrcomDNS1) +
		fmt.Sprintf("DrcomDNS2: %s", info.DrcomDNS2) +
		fmt.Sprintf("DrcomSvrPort: %d", info.DrcomSvrPort) +
		"==================================================\n"
}

func (info *DrcomInfo) getLocalMac() net.HardwareAddr {
	return info.ifc.NetTarget.HardwareAddr
}

func (info *DrcomInfo) SetDefault() {
	info.DrcomSvrAddr = DrcomServerAddr
	info.DrcomDNS1 = DrcomDNS1Addr
	info.DrcomDNS2 = DrcomDNS2Addr
	info.DrcomSvrPort = DrcomServerPort
}

func CreateDrcomInfoTemplate(idx int, parse *map[string]IfcParse) *DrcomInfo {
	for ip, val := range *parse {
		if val.index == idx {
			return &DrcomInfo{
				ifc:     &val,
				LocalIP: net.ParseIP(ip),
			}
		}
	}
	return nil
}

// Handle class start

// Handle definition
type Handle struct {
	PcapHandle *pcap.Handle

	// for 802.1x auth
	srcMacAddr, dstMacAddr net.HardwareAddr
	svrMacAddr             net.HardwareAddr
	buffer                 gopacket.SerializeBuffer
	options                gopacket.SerializeOptions

	// for drcom ( udp ) auth
	udpAuthConn *net.UDPConn
}

// always use this function to create a handle
func HandleFromInfo(info *DrcomInfo) (*Handle, error) {
	handler, err := pcap.OpenLive(info.ifc.PcapName, 1024, false, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp", &net.UDPAddr{IP: info.LocalIP}, &net.UDPAddr{IP: info.DrcomSvrAddr, Port: info.DrcomSvrPort})
	if err != nil {
		return nil, err
	}
	return &Handle{
		PcapHandle: handler,
		srcMacAddr: info.getLocalMac(),
		dstMacAddr: MultiCastAddr,
		buffer:     gopacket.NewSerializeBuffer(),
		options:    gopacket.SerializeOptions{FixLengths: false, ComputeChecksums: true},

		udpAuthConn: conn,
	}, nil
}

// nolonger used
func NewHandle(dev *pcap.Interface, srcMacAddr net.HardwareAddr) (*Handle, error) {
	handler, err := pcap.OpenLive(dev.Name, 1024, false, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	h := &Handle{
		PcapHandle: handler,
		srcMacAddr: srcMacAddr,
		dstMacAddr: MultiCastAddr,
		buffer:     gopacket.NewSerializeBuffer(),
		options:    gopacket.SerializeOptions{FixLengths: false, ComputeChecksums: true},
	}
	return h, nil
}

// destructor
func (h *Handle) Close() {
	h.PcapHandle.Close()
}

// Properties
func (h *Handle) SetDstMacAddr(addr net.HardwareAddr) {
	if bytes.Compare(h.dstMacAddr, MultiCastAddr) == 0 {
		h.dstMacAddr = addr
	}
}

// Global send implement
func (h *Handle) send(paras ...gopacket.SerializableLayer) error {
	if err := gopacket.SerializeLayers(h.buffer, h.options, paras...); err != nil {
		return err
	}
	return h.PcapHandle.WritePacketData(h.buffer.Bytes())
}

// Methods

func (h *Handle) SendLogoffPkt() error {
	eth := layers.Ethernet{
		SrcMAC:       h.srcMacAddr,
		DstMAC:       h.dstMacAddr,
		EthernetType: layers.EthernetTypeEAPOL,
	}
	eapol := layers.EAPOL{
		Version: 0x01,
		Type:    layers.EAPOLTypeLogOff,
	}
	if err := h.send(&eth, &eapol); err != nil {
		return err
	}

	return nil
}

func (h *Handle) SendResponseIdentity(id uint8, identity []byte) error {
	eth := layers.Ethernet{
		SrcMAC:       h.srcMacAddr,
		DstMAC:       h.dstMacAddr,
		EthernetType: layers.EthernetTypeEAPOL,
	}
	eapol := layers.EAPOL{
		Version: 0x01,
		Type:    layers.EAPOLTypeEAP,
		Length:  uint16(0x10),
	}
	eap := layers.EAP{
		Code:     layers.EAPCodeResponse,
		Id:       id,
		Type:     layers.EAPTypeIdentity,
		TypeData: identity,
		Length:   uint16(0x10),
	}
	if err := h.send(&eth, &eapol, &eap, &fillLayer); err != nil {
		return err
	}
	return nil
}

func (h *Handle) SendResponseMD5Chall(id uint8, salt, user, pass []byte) error {
	plain := []byte{id}
	plain = append(plain, pass...)
	plain = append(plain, salt[:0x10]...)
	cipher := md5.Sum(plain)
	data := append([]byte{uint8(len(cipher))}, cipher[:]...)
	data = append(data, user...)
	eth := layers.Ethernet{
		SrcMAC:       h.srcMacAddr,
		DstMAC:       h.dstMacAddr,
		EthernetType: layers.EthernetTypeEAPOL,
	}
	eapol := layers.EAPOL{
		Version: 0x01,
		Type:    layers.EAPOLTypeEAP,
		Length:  uint16(5 + len(data)),
	}
	eap := layers.EAP{
		Code:     layers.EAPCodeResponse,
		Id:       id,
		Type:     layers.EAPTypeOTP,
		TypeData: data,
		Length:   eapol.Length,
	}
	if err := h.send(&eth, &eapol, &eap, &fillLayer); err != nil {
		return err
	}
	return nil
}

func (h *Handle) SendStartPkt() error {
	if h.dstMacAddr == nil {
		h.dstMacAddr = MultiCastAddr
	} else if h.dstMacAddr[1] == 0xff {
		h.dstMacAddr = MultiCastAddr
	} else if h.dstMacAddr[1] == 0x80 {
		h.dstMacAddr = BroadcastAddr
	}

	eth := layers.Ethernet{
		SrcMAC:       h.srcMacAddr,
		DstMAC:       h.dstMacAddr,
		EthernetType: layers.EthernetTypeEAPOL,
	}

	eapol := layers.EAPOL{
		Version: 0x01,
		Type:    layers.EAPOLTypeStart,
	}
	if err := h.send(&eth, &eapol, &fillLayer); err != nil {
		return err
	}
	return nil
}

var startPkt = []byte{0x07, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00}

func (h *Handle) DrcomMiscStart() error {
	length, err := h.udpAuthConn.Write(startPkt)
	if length != len(startPkt) {
		return errors.New("DrcomMiscStart: Write length error")
	}
	return err
}
