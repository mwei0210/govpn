package client

import (
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/agl/ed25519"

	"cypherpunks.ru/govpn"
)

type Protocol uint8

const (
	ProtocolUDP Protocol = iota
	ProtocolTCP
)

type Configuration struct {
	PrivateKey          *[ed25519.PrivateKeySize]byte
	Peer                *govpn.PeerConf
	Protocol            Protocol
	InterfaceName       string
	ProxyAddress        string
	ProxyAuthentication string
	RemoteAddress       string
	UpPath, DownPath    string
	StatsAddress        string
	NoReconnect         bool
	MTU                 int
}

func (c *Configuration) Validate() error {
	if c.MTU > govpn.MTUMax {
		return fmt.Errorf("Invalid MTU %d, maximum allowable is %d", c.MTU, govpn.MTUMax)
	}
	if len(c.RemoteAddress) == 0 {
		return errors.New("Missing RemoteAddress")
	}
	if len(c.InterfaceName) == 0 {
		return errors.New("Missing InterfaceName")
	}
	return nil
}

func (c *Configuration) isProxy() bool {
	return len(c.ProxyAddress) > 0
}

type Client struct {
	idsCache      *govpn.MACCache
	tap           *govpn.TAP
	knownPeers    govpn.KnownPeers
	statsPort     net.Listener
	timeouted     chan struct{}
	rehandshaking chan struct{}
	termination   chan struct{}
	firstUpCall   bool
	termSignal    chan os.Signal
	config        Configuration

	// Error receive any error of all routines
	Error chan error
}

func (c *Client) MainCycle() {
	var err error
	c.tap, err = govpn.TAPListen(c.config.InterfaceName, c.config.MTU)
	if err != nil {
		c.Error <- fmt.Errorf("Can not listen on TUN/TAP interface: %s", err.Error())
		return
	}

	if len(c.config.StatsAddress) > 0 {
		c.statsPort, err = net.Listen("tcp", c.config.StatsAddress)
		if err != nil {
			c.Error <- fmt.Errorf("Can't listen on stats port: %s", err.Error())
			return
		}
		c.knownPeers = govpn.KnownPeers(make(map[string]**govpn.Peer))
		go govpn.StatsProcessor(c.statsPort, &c.knownPeers)
	}

MainCycle:
	for {
		c.timeouted = make(chan struct{})
		c.rehandshaking = make(chan struct{})
		c.termination = make(chan struct{})
		switch c.config.Protocol {
		case ProtocolUDP:
			go c.startUDP()
		case ProtocolTCP:
			if c.config.isProxy() {
				go c.proxyTCP()
			} else {
				go c.startTCP()
			}
		}
		select {
		case <-c.termSignal:
			govpn.BothPrintf(`[finish remote="%s"]`, c.config.RemoteAddress)
			c.termination <- struct{}{}
			// send a non-error to let know everything went fine
			c.Error <- nil
			break MainCycle
		case <-c.timeouted:
			if c.config.NoReconnect {
				break MainCycle
			}
			govpn.BothPrintf(`[sleep seconds="%d"]`, c.config.Peer.Timeout)
			time.Sleep(c.config.Peer.Timeout)
		case <-c.rehandshaking:
		}
		close(c.timeouted)
		close(c.rehandshaking)
		close(c.termination)
	}
	if _, err = govpn.ScriptCall(c.config.DownPath, c.config.InterfaceName, c.config.RemoteAddress); err != nil {
		c.Error <- err
	}
}

func NewClient(conf Configuration, verifier *govpn.Verifier, termSignal chan os.Signal) *Client {
	client := &Client{
		idsCache:    govpn.NewMACCache(),
		firstUpCall: true,
		config:      conf,
		termSignal:  termSignal,
		Error:       make(chan error, 1),
	}
	confs := map[govpn.PeerId]*govpn.PeerConf{*verifier.Id: conf.Peer}
	client.idsCache.Update(&confs)
	return client
}
