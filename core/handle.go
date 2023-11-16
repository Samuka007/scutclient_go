package scutclient_go

/*
	Device for ETH_EAP authentication
	Adapter for UDP authentication
*/

import (
	"bytes"
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

// Handle class start

// Handle definition
type Handle struct {
	PcapHandle             *pcap.Handle
	srcMacAddr, dstMacAddr net.HardwareAddr
	buffer                 gopacket.SerializeBuffer
	options                gopacket.SerializeOptions
}

// constructor
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
