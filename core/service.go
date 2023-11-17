package scutclient_go

import (
	// "encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type SrvStat int

const (
	SrvStatStart = SrvStat(iota)
	SrvStatRespIdentity
	SrvStatRespMd5Chall
	SrvStatSuccess
	SrvStatFailure
	SrvStatKeepAlive
	SrvStatError
)

const (
	AUTH_8021X_RECV_TIMES = 3
)

func (s SrvStat) String() string {
	switch s {
	case SrvStatStart:
		return "请求认证..."
	case SrvStatRespIdentity:
		return "开始认证..."
	case SrvStatRespMd5Chall:
		return "认证中..."
	case SrvStatKeepAlive:
		return "保持认证状态"
	case SrvStatSuccess:
		return "认证成功"
	case SrvStatFailure:
		return "认证失败"
	case SrvStatError:
		return "内部错误"
	}
	return "未知错误"
}

type Service struct {
	State           SrvStat
	user, pass      []byte
	device, adapter string
	handle          *Handle
	echoNo, echoKey uint32
	advertising     string
	// 8021x auth pkts
	pkt8021x chan gopacket.Packet
	// udp auth pkts
	pktUdp chan gopacket.Packet
	// global pkts
	// chanPkts		chan gopacket.Packet
	threadLock   sync.Mutex
	crontab      *Crontab
	retryTimes   int
	isClosed     bool
	isStopped    bool
	logOffBefore bool
}

func NewService(usr, pass, dev, adap string) (*Service, error) {
	ifc, err := SelectNetworkDev(dev)
	if err != nil {
		return nil, err
	}
	macAddr, err := SelectNetworkAdapter(adap)
	if err != nil {
		return nil, err
	}
	hnd, err := NewHandle(ifc, macAddr)
	if err != nil {
		return nil, err
	}
	return &Service{
		user:    []byte(usr),
		pass:    []byte(pass),
		device:  dev,
		adapter: adap,
		handle:  hnd,
		State:   SrvStatFailure,
		// chanPkt: make(chan gopacket.Packet, 1024),
		crontab: NewCrontab(),
	}, nil
}

// Ethernet Type packets
func (s *Service) packets8021x() (<-chan gopacket.Packet, error) {
	if s.pkt8021x != nil {
		return s.pkt8021x, nil
	}
	s.pkt8021x = make(chan gopacket.Packet, 1000)
	go func() {
		defer close(s.pkt8021x)
		src := gopacket.NewPacketSource(s.handle.PcapHandle, layers.LayerTypeEthernet)
		in := src.Packets()
		for packet := range in {
			if s.isClosed {
				break
			}
			pkt := packet.Layer(layers.LayerTypeEAP)
			if pkt == nil {
				continue
			}
			s.pkt8021x <- packet
		}
	}()
	return s.pkt8021x, nil
}

func (s *Service) packetsUdp() (<-chan gopacket.Packet, error) {
	if s.pktUdp != nil {
		return s.pktUdp, nil
	}
	s.pktUdp = make(chan gopacket.Packet, 1000)
	go func() {
		defer close(s.pktUdp)
		src := gopacket.NewPacketSource(s.handle.PcapHandle, layers.LayerTypeUDP)
		in := src.Packets()
		for packet := range in {
			if s.isClosed {
				break
			}
			pkt := packet.Layer(layers.LayerTypeUDP)
			if pkt == nil {
				continue
			}
			s.pktUdp <- packet
		}
	}()
	return s.pktUdp, nil
}

func getSrcMac(packet gopacket.Packet) net.HardwareAddr {
	return packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet).SrcMAC
}

func DrcomEAPErrParse(data []byte) string {
	str := string(data)
	if strings.HasPrefix(str, "userid error") {
		errcode, _ := strconv.Atoi(str[12:])
		switch errcode {
		case 1:
			return "Account does not exist."
		case 2, 3:
			return "Username or password invalid."
		case 4:
			return "This account might be expended."
		default:
			return str
		}
	} else if strings.HasPrefix(str, "Authentication Fail ErrCode=") {
		errcode, _ := strconv.Atoi(str[27:])
		switch errcode {
		case 0:
			return "Username or password invalid."
		case 5:
			return "This account is suspended."
		case 9:
			return "This account might be expended."
		case 11:
			return "You are not allowed to perform a radius authentication."
		case 16:
			// timeNotAllowed = 1
			return "You are not allowed to access the internet now."
		case 30, 63:
			return "No more time available for this account."
		default:
			return str
		}
	} else if strings.HasPrefix(str, "AdminReset") {
		return str
	} else if strings.Contains(str, "Mac, IP, NASip, PORT") {
		return "You are not allowed to login using current IP/MAC address."
	} else if strings.Contains(str, "flowover") {
		return "Data usage has reached the limit."
	} else if strings.Contains(str, "In use") {
		return "This account is in use."
	}
	return ""
}

func (s *Service) handle8021xPkt(packet gopacket.Packet) error {
	eap := packet.Layer(layers.LayerTypeEAP).(*layers.EAP)
	switch eap.Code {
	case layers.EAPCodeRequest:
		switch eap.Type {

		// Identity
		case layers.EAPTypeIdentity:
			s.updateStat(SrvStatRespIdentity)
			return s.handle.SendResponseIdentity(eap.Id, s.user)

		// MD5 challenge
		case layers.EAPTypeOTP:
			s.updateStat(SrvStatRespMd5Chall)
			return s.handle.SendResponseMD5Chall(eap.Id, eap.Contents, s.user, s.pass)

		// Notification
		case layers.EAPTypeNotification:
			if err := DrcomEAPErrParse(eap.Contents); err != "" {
				s.updateStat(SrvStatError)
				return fmt.Errorf(err)
			}
			// log info notification
		}
	case layers.EAPCodeFailure:
		s.updateStat(SrvStatFailure)
		// if retry time > 0
		// retry time--
		// set status retry
		// else
		// set status failure
		// return fmt.Errorf("Reconnection failed. Server: %d", eap.Type)
	case layers.EAPCodeSuccess:
		s.updateStat(SrvStatSuccess)
		s.retryTimes = AUTH_8021X_RECV_TIMES
		time.Sleep(1 * time.Second)
		// setting heartbeats
		return s.handle.DrcomMiscStart()

	default:
		s.updateStat(SrvStatError)
		return fmt.Errorf("Unknown EAP Code %d", eap.Code)
	}
	return nil
}

func (s *Service) proxy8021x() error {

	return nil
}

func (s *Service) handleUdp() error {
	in, err := s.packetsUdp()
	if err != nil {
		return err
	}
	for packet := range in {
		if s.isClosed {
			break
		}
		if s.isStopped {
			s.crontab.UpdateLastAccess("Echo", time.Now())
			s.crontab.UpdateLastAccess("Monitor", time.Now())
			continue
		}
		udp := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
		if udp.SrcPort == 2000 {
			s.updateStat(SrvStatKeepAlive)
			// s.handle.SendEchoPkt(s.echoNo, s.echoKey)
			// s.echoNo++
		}
	}
	return nil
}

func (s *Service) initLogoff() error {
	in, err := s.packets8021x()
	if err != nil {
		return err
	}
	for i := 2; i > 0; i-- {
		err = s.handle.SendLogoffPkt()
		if err != nil {
			return err
		}
		// wait for response or 0.5s timeout
		select {
		case packet := <-in:
			packet8021x := packet.Layer(layers.LayerTypeEAP).(*layers.EAP)
			if packet8021x.Code == layers.EAPCodeFailure {
				s.logOffBefore = true
				continue
			}
		case <-time.After(500 * time.Millisecond):
			continue
		}
	}
	return nil
}

func (s *Service) login() error {
	err := s.handle.SendStartPkt()
	if err != nil {
		return err
	}

	in, err := s.packets8021x()
	if err != nil {
		return err
	}

	for i := 3; i > 0; i-- {
		select {

		case pkt := <-in:
			s.handle.svrMacAddr = getSrcMac(pkt)
			// good to start main auth
			return s.handle8021xPkt(pkt)

		case <-time.After(1 * time.Second):
			err := s.handle.SendStartPkt()
			if err != nil {
				return err
			}
		}
	}
	return errors.New("No response.")
}

func (s *Service) Authenticate() error {
	s.threadLock.Lock()
	defer s.threadLock.Unlock()

	err := s.initLogoff()
	if err != nil {
		return err
	}

	if s.logOffBefore {
		s.logOffBefore = false
		time.Sleep(2 * time.Second)
	}

	// logoff success, start auth
	s.updateStat(SrvStatStart)

	// go 802.1x auth
	// go udp auth ( udp for heart beat authorize )
	return nil
}

func (s *Service) updateStat(stat SrvStat) {
	s.crontab.UpdateLastAccess("Monitor", time.Now())
	s.State = stat
}

func (s *Service) Continue() {
	s.isStopped = false
	s.handle.SendStartPkt()
}

func (s *Service) Stop() {
	s.isStopped = true
	s.handle.SendLogoffPkt()
}

func (s *Service) Close() {
	log.Printf("closing RJSocks service\n")
	s.handle.SendLogoffPkt()
	s.handle.Close()
	s.crontab.Close()
	s.isClosed = true
}
