/*
GoVPN -- simple secure free software virtual private network daemon
Copyright (C) 2014-2016 Sergey Matveev <stargrave@stargrave.org>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package govpn

import (
	"bytes"
	"crypto/subtle"
	"encoding/binary"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"chacha20"
	"github.com/Sirupsen/logrus"
	"github.com/pkg/errors"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/poly1305"
)

const (
	// NonceSize is nounce size
	NonceSize                 = 8
	nonceBucketSize           = 256
	tagSize                   = poly1305.TagSize
	chacha20InternalBlockSize = 64
	// MaxBytesPerKey maximal amount of bytes transfered with single key (4 GiB)
	MaxBytesPerKey uint64 = 1 << 32
	// heartbeat rate, relative to Timeout
	timeoutHeartbeat = 4
	// MinPktLength minimal valid packet length
	MinPktLength = 1 + 16 + 8
	// padding byte
	padByte = byte(0x80)

	logPrefixPeer = "peer_"
)

func newNonces(key *[32]byte, i uint64) (chan *[NonceSize]byte, error) {
	macKey := make([]byte, 32)
	chacha20.XORKeyStream(macKey, make([]byte, 32), new([16]byte), key)
	mac, err := blake2b.New256(macKey)
	if err != nil {
		panic(err)
	}
	sum := make([]byte, mac.Size())
	nonces := make(chan *[NonceSize]byte, nonceBucketSize*3)
	go func() {
		for {
			buf := new([NonceSize]byte)
			binary.BigEndian.PutUint64(buf[:], i)
			mac.Write(buf[:])
			mac.Sum(sum[0:])
			copy(buf[:], sum)
			nonces <- buf
			mac.Reset()
			i += 2
		}
	}()
	return nonces, nil
}

// Peer is a GoVPN peer (client)
type Peer struct {
	// Statistics (they are at the beginning for correct int64 alignment)
	BytesIn         uint64
	BytesOut        uint64
	BytesPayloadIn  uint64
	BytesPayloadOut uint64
	FramesIn        uint64
	FramesOut       uint64
	FramesUnauth    uint64
	FramesDup       uint64
	HeartbeatRecv   uint64
	HeartbeatSent   uint64

	// Basic
	Addr     string
	ID       *PeerID
	Conn     io.Writer `json:"-"`
	Protocol Protocol

	// Traffic behaviour
	NoiseEnable bool
	CPR         int
	CPRCycle    time.Duration `json:"-"`
	Encless     bool
	MTU         int

	key *[SSize]byte

	// Timers
	Timeout     time.Duration `json:"-"`
	Established time.Time
	LastPing    time.Time

	// Receiver
	BusyR    sync.Mutex `json:"-"`
	bufR     []byte
	tagR     *[tagSize]byte
	keyAuthR *[SSize]byte
	nonceR   *[16]byte
	pktSizeR int

	// UDP-related
	noncesR      chan *[NonceSize]byte
	nonceRecv    [NonceSize]byte
	nonceBucketL map[[NonceSize]byte]struct{}
	nonceBucketM map[[NonceSize]byte]struct{}
	nonceBucketH map[[NonceSize]byte]struct{}

	// TCP-related
	NonceExpect  []byte `json:"-"`
	noncesExpect chan *[NonceSize]byte

	// Transmitter
	BusyT    sync.Mutex `json:"-"`
	bufT     []byte
	tagT     *[tagSize]byte
	keyAuthT *[SSize]byte
	nonceT   *[16]byte
	frameT   []byte
	noncesT  chan *[NonceSize]byte
}

// LogFields return a logrus compatible Fields to identity a single peer in logs
func (p *Peer) LogFields() logrus.Fields {
	return logrus.Fields{
		logPrefixPeer + "addr":        p.Addr,
		logPrefixPeer + "id":          p.ID.String(),
		logPrefixPeer + "established": p.Established.String(),
		logPrefixPeer + "last_ping":   p.LastPing.String(),
	}
}

// ConfigurationLogFields return a logrus compatible Fields with the settings of
// a single peer. Complement LogFields() for extra debugging details.
func (p *Peer) ConfigurationLogFields() logrus.Fields {
	return logrus.Fields{
		logPrefixPeer + "timeout":  p.Timeout.String(),
		logPrefixPeer + "protocol": p.Protocol.String(),
		logPrefixPeer + "noise":    p.NoiseEnable,
		logPrefixPeer + "cpr":      p.CPR,
		logPrefixPeer + "mtu":      p.MTU,
		logPrefixPeer + "encless":  p.Encless,
	}
}

func (p *Peer) String() string {
	return p.ID.String() + ":" + p.Addr
}

// Zero peer's memory state.
func (p *Peer) Zero() {
	p.BusyT.Lock()
	p.BusyR.Lock()
	SliceZero(p.key[:])
	SliceZero(p.bufR)
	SliceZero(p.bufT)
	SliceZero(p.keyAuthR[:])
	SliceZero(p.keyAuthT[:])
	p.BusyT.Unlock()
	p.BusyR.Unlock()
}

func cprCycleCalculate(conf *PeerConf) time.Duration {
	if conf.CPR == 0 {
		return time.Duration(0)
	}
	rate := conf.CPR * 1 << 10
	if conf.Encless {
		rate /= EnclessEnlargeSize + conf.MTU
	} else {
		rate /= conf.MTU
	}
	return time.Second / time.Duration(rate)
}

func newPeer(isClient bool, addr string, conn io.Writer, conf *PeerConf, key *[SSize]byte) (*Peer, error) {
	now := time.Now()
	timeout := conf.Timeout

	cprCycle := cprCycleCalculate(conf)
	noiseEnable := conf.Noise
	if conf.CPR > 0 {
		noiseEnable = true
		timeout = cprCycle
	} else {
		timeout = timeout / timeoutHeartbeat
	}

	bufSize := chacha20InternalBlockSize + 2*conf.MTU
	if conf.Encless {
		bufSize += EnclessEnlargeSize
		noiseEnable = true
	}

	peer := Peer{
		Addr: addr,
		ID:   conf.ID,
		Conn: conn,

		NoiseEnable: noiseEnable,
		CPR:         conf.CPR,
		CPRCycle:    cprCycle,
		Encless:     conf.Encless,
		MTU:         conf.MTU,

		key: key,

		Timeout:     timeout,
		Established: now,
		LastPing:    now,

		bufR:     make([]byte, bufSize),
		bufT:     make([]byte, bufSize),
		tagR:     new([tagSize]byte),
		tagT:     new([tagSize]byte),
		keyAuthR: new([SSize]byte),
		nonceR:   new([16]byte),
		keyAuthT: new([SSize]byte),
		nonceT:   new([16]byte),
	}

	var err error
	if isClient {
		if peer.noncesT, err = newNonces(peer.key, 1+2); err != nil {
			return nil, err
		}
		if peer.noncesR, err = newNonces(peer.key, 0+2); err != nil {
			return nil, err
		}
		if peer.noncesExpect, err = newNonces(peer.key, 0+2); err != nil {
			return nil, err
		}
	} else {
		if peer.noncesT, err = newNonces(peer.key, 0+2); err != nil {
			return nil, err
		}
		if peer.noncesR, err = newNonces(peer.key, 1+2); err != nil {
			return nil, err
		}
		if peer.noncesExpect, err = newNonces(peer.key, 1+2); err != nil {
			return nil, err
		}
	}

	peer.NonceExpect = make([]byte, NonceSize)
	nonce := <-peer.noncesExpect
	copy(peer.NonceExpect, nonce[:])

	var i int
	peer.nonceBucketL = make(map[[NonceSize]byte]struct{}, nonceBucketSize)
	for i = 0; i < nonceBucketSize; i++ {
		nonce = <-peer.noncesR
		peer.nonceBucketL[*nonce] = struct{}{}
	}
	peer.nonceBucketM = make(map[[NonceSize]byte]struct{}, nonceBucketSize)
	for i = 0; i < nonceBucketSize; i++ {
		nonce = <-peer.noncesR
		peer.nonceBucketM[*nonce] = struct{}{}
	}
	peer.nonceBucketH = make(map[[NonceSize]byte]struct{}, nonceBucketSize)
	for i = 0; i < nonceBucketSize; i++ {
		nonce = <-peer.noncesR
		peer.nonceBucketH[*nonce] = struct{}{}
	}

	return &peer, nil
}

// EthProcess process incoming Ethernet packet.
// ready channel is TAPListen's synchronization channel used to tell him
// that he is free to receive new packets. Encrypted and authenticated
// packets will be sent to remote Peer side immediately.
func (p *Peer) EthProcess(data []byte) error {
	const paddingSize = 1
	lenData := len(data)
	if lenData > p.MTU-paddingSize {
		logger.WithFields(p.LogFields()).WithFields(p.ConfigurationLogFields()).WithFields(
			logrus.Fields{
				"func":        logFuncPrefix + "Peer.EthProcess",
				"padding":     paddingSize,
				"packet_size": lenData,
			}).Warning("Ignore padded data packet larger than MTU")
		return nil
	}
	p.BusyT.Lock()
	defer p.BusyT.Unlock()

	// Zero size is a heartbeat packet
	SliceZero(p.bufT)
	if lenData == 0 {
		p.bufT[chacha20InternalBlockSize+0] = padByte
		p.HeartbeatSent++
	} else {
		// Copy payload to our internal buffer and we are ready to
		// accept the next one
		copy(p.bufT[chacha20InternalBlockSize:], data)
		p.bufT[chacha20InternalBlockSize+lenData] = padByte
		p.BytesPayloadOut += uint64(lenData)
	}

	if p.NoiseEnable && !p.Encless {
		p.frameT = p.bufT[chacha20InternalBlockSize : chacha20InternalBlockSize+p.MTU-tagSize]
	} else if p.Encless {
		p.frameT = p.bufT[chacha20InternalBlockSize : chacha20InternalBlockSize+p.MTU]
	} else {
		p.frameT = p.bufT[chacha20InternalBlockSize : chacha20InternalBlockSize+lenData+1+NonceSize]
	}
	copy(p.frameT[len(p.frameT)-NonceSize:], (<-p.noncesT)[:])
	var out []byte
	copy(p.nonceT[8:], p.frameT[len(p.frameT)-NonceSize:])
	if p.Encless {
		var err error
		out, err = EnclessEncode(p.key, p.nonceT, p.frameT[:len(p.frameT)-NonceSize])
		if err != nil {
			return errors.Wrap(err, wrapEnclessEncode)
		}
		out = append(out, p.frameT[len(p.frameT)-NonceSize:]...)
	} else {
		chacha20.XORKeyStream(
			p.bufT[:chacha20InternalBlockSize+len(p.frameT)-NonceSize],
			p.bufT[:chacha20InternalBlockSize+len(p.frameT)-NonceSize],
			p.nonceT,
			p.key,
		)
		copy(p.keyAuthT[:], p.bufT[:SSize])
		poly1305.Sum(p.tagT, p.frameT, p.keyAuthT)
		atomic.AddUint64(&p.BytesOut, uint64(len(p.frameT)+tagSize))
		out = append(p.tagT[:], p.frameT...)
	}
	p.FramesOut++
	_, err := p.Conn.Write(out)
	return errors.Wrap(err, "p.Conn.Write")
}

// PktProcess process data of a single packet
func (p *Peer) PktProcess(data []byte, tap io.Writer, reorderable bool) bool {
	lenData := len(data)
	fields := logrus.Fields{
		"func":        logFuncPrefix + "Peer.PktProcess",
		"reorderable": reorderable,
		"data":        lenData,
	}
	if lenData < MinPktLength {
		logger.WithFields(p.LogFields()).WithFields(fields).WithField("minimum_packet_Length", MinPktLength).Debug("Ignore packet smaller than allowed minimum")
		return false
	}
	if !p.Encless && lenData > len(p.bufR)-chacha20InternalBlockSize {
		return false
	}
	var out []byte
	p.BusyR.Lock()
	defer p.BusyR.Unlock()
	copy(p.nonceR[8:], data[lenData-NonceSize:])
	if p.Encless {
		var err error
		out, err = EnclessDecode(p.key, p.nonceR, data[:lenData-NonceSize])
		if err != nil {
			logger.WithFields(p.LogFields()).WithError(err).Debug("Failed to decode encless")
			p.FramesUnauth++
			return false
		}
	} else {
		for i := 0; i < SSize; i++ {
			p.bufR[i] = 0
		}
		copy(p.bufR[chacha20InternalBlockSize:], data[tagSize:])
		chacha20.XORKeyStream(
			p.bufR[:chacha20InternalBlockSize+lenData-tagSize-NonceSize],
			p.bufR[:chacha20InternalBlockSize+lenData-tagSize-NonceSize],
			p.nonceR,
			p.key,
		)
		copy(p.keyAuthR[:], p.bufR[:SSize])
		copy(p.tagR[:], data[:tagSize])
		if !poly1305.Verify(p.tagR, data[tagSize:], p.keyAuthR) {
			p.FramesUnauth++
			return false
		}
		out = p.bufR[chacha20InternalBlockSize : chacha20InternalBlockSize+lenData-tagSize-NonceSize]
	}

	if reorderable {
		copy(p.nonceRecv[:], data[lenData-NonceSize:])
		_, foundL := p.nonceBucketL[p.nonceRecv]
		_, foundM := p.nonceBucketM[p.nonceRecv]
		_, foundH := p.nonceBucketH[p.nonceRecv]
		// If found is none of buckets: either it is too old,
		// or too new (many packets were lost)
		if !(foundL || foundM || foundH) {
			p.FramesDup++
			return false
		}
		// Delete seen nonce
		if foundL {
			delete(p.nonceBucketL, p.nonceRecv)
		}
		if foundM {
			delete(p.nonceBucketM, p.nonceRecv)
		}
		if foundH {
			delete(p.nonceBucketH, p.nonceRecv)
		}
		// If we are dealing with the latest bucket, create the new one
		if foundH {
			p.nonceBucketL, p.nonceBucketM = p.nonceBucketM, p.nonceBucketH
			p.nonceBucketH = make(map[[NonceSize]byte]struct{})
			var nonce *[NonceSize]byte
			for i := 0; i < nonceBucketSize; i++ {
				nonce = <-p.noncesR
				p.nonceBucketH[*nonce] = struct{}{}
			}
		}
	} else {
		if subtle.ConstantTimeCompare(data[lenData-NonceSize:], p.NonceExpect) != 1 {
			p.FramesDup++
			return false
		}
		copy(p.NonceExpect, (<-p.noncesExpect)[:])
	}

	p.FramesIn++
	atomic.AddUint64(&p.BytesIn, uint64(lenData))
	p.LastPing = time.Now()
	p.pktSizeR = bytes.LastIndexByte(out, padByte)
	if p.pktSizeR == -1 {
		return false
	}
	// Validate the pad
	for i := p.pktSizeR + 1; i < len(out); i++ {
		if out[i] != 0 {
			return false
		}
	}

	if p.pktSizeR == 0 {
		p.HeartbeatRecv++
		return true
	}
	p.BytesPayloadIn += uint64(p.pktSizeR)
	tap.Write(out[:p.pktSizeR])
	return true
}

// PeerTapProcessor process a TUN/TAP peer
func PeerTapProcessor(peer *Peer, tap *TAP, terminator chan struct{}) {
	var data []byte
	var now time.Time
	var err error
	fields := logrus.Fields{
		"func": logFuncPrefix + "PeerTapProcessor",
		"tap":  tap.Name,
	}
	lastSent := time.Now()
	heartbeat := time.NewTicker(peer.Timeout)
	if peer.CPRCycle == time.Duration(0) {
	RawProcessor:
		for {
			select {
			case <-terminator:
				break RawProcessor
			case <-heartbeat.C:
				now = time.Now()
				if lastSent.Add(peer.Timeout).Before(now) {
					if err = peer.EthProcess(nil); err != nil {
						logger.WithFields(fields).WithFields(peer.LogFields()).WithError(err).Warn("Can't process nil ethernet packet")
					}
					lastSent = now
				}
			case data = <-tap.Sink:
				if err = peer.EthProcess(data); err != nil {
					logger.WithFields(fields).WithFields(peer.LogFields()).WithError(err).Warn("Can't process ethernet packet")
				}
				lastSent = time.Now()
			}
		}
	} else {
	CPRProcessor:
		for {
			data = nil
			select {
			case <-terminator:
				break CPRProcessor
			case data = <-tap.Sink:
				if err = peer.EthProcess(data); err != nil {
					logger.WithFields(fields).WithFields(peer.LogFields()).WithError(err).Warn("Can't process ethernet packet")
				}
			default:
			}
			if data == nil {
				if err = peer.EthProcess(nil); err != nil {
					logger.WithFields(fields).WithFields(peer.LogFields()).WithError(err).Warn("Can't process nil ethernet packet")
				}
			}
			time.Sleep(peer.CPRCycle)
		}
	}
	close(terminator)
	peer.Zero()
	heartbeat.Stop()
}
