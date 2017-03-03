/*
GoVPN -- simple secure free software virtual private network daemon
Copyright (C) 2014-2017 Sergey Matveev <stargrave@stargrave.org>

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
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"sync"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/pkg/errors"
	"golang.org/x/crypto/blake2b"
)

// IDSize is a size of GoVPN peer's identity
const IDSize = 128 / 8

// PeerID is identifier of a single GoVPN peer (client)
type PeerID [IDSize]byte

// String returns peer's ID in stringified form
func (id PeerID) String() string {
	return base64.RawStdEncoding.EncodeToString(id[:])
}

// MarshalJSON returns a JSON serialized peer's ID
func (id PeerID) MarshalJSON() ([]byte, error) {
	return []byte(`"` + id.String() + `"`), nil
}

// MACAndTimeSync is a single peer MAC and timesync
type MACAndTimeSync struct {
	mac hash.Hash
	ts  int
	l   sync.Mutex
}

// MACCache caches all MACAndTimeSync for peers allowed to connect
type MACCache struct {
	cache map[PeerID]*MACAndTimeSync
	l     sync.RWMutex
}

// Length returns size of MACCache
func (mc *MACCache) Length() int {
	return len(mc.cache)
}

// NewMACCache returns a new MACCache instance
func NewMACCache() *MACCache {
	return &MACCache{cache: make(map[PeerID]*MACAndTimeSync)}
}

// Update removes disappeared keys, add missing ones with initialized MACs.
func (mc *MACCache) Update(peers *map[PeerID]*PeerConf) error {
	mc.l.Lock()
	defer mc.l.Unlock()
	fields := logrus.Fields{
		"func":  logFuncPrefix + "MACCache.Update",
		"peers": len(*peers),
	}
	logger.WithFields(fields).WithField("size", mc.Length()).Debug("Cleaning old keys")
	for pid := range mc.cache {
		if _, exists := (*peers)[pid]; !exists {
			logger.WithFields(fields).WithField("pid", pid).Debug("Cleaning key")
			delete(mc.cache, pid)
		}
	}
	logger.WithFields(
		fields,
	).WithField(
		"size",
		mc.Length(),
	).Debug("Cleaned, adding/updating new keys")
	for pid, pc := range *peers {
		if _, exists := mc.cache[pid]; exists {
			logger.WithFields(fields).WithFields(
				logrus.Fields{
					"pid":    pid.String(),
					"old_ts": mc.cache[pid].ts,
					"new_ts": pc.TimeSync,
				}).Debug("Rest timesync")
			mc.cache[pid].ts = pc.TimeSync
		} else {
			before := time.Now()
			mac, err := blake2b.New256(pid[:])
			if err != nil {
				return errors.Wrap(err, wrapBlake2bNew256)
			}
			logger.WithFields(fields).WithFields(logrus.Fields{
				"pid":     pid.String(),
				"ts":      pc.TimeSync,
				"elapsed": time.Now().Sub(before).String(),
			}).Debug("Adding key")
			mc.cache[pid] = &MACAndTimeSync{
				mac: mac,
				ts:  pc.TimeSync,
			}
		}
	}
	logger.WithFields(fields).WithField("size", mc.Length()).Debug("Finished")
	return nil
}

// AddTimeSync XORs timestamp with data if timeSync > 0
func AddTimeSync(ts int, data []byte) {
	fields := logrus.Fields{
		"func":      logFuncPrefix + "AddTimeSync",
		"ts":        ts,
		"data_size": len(data),
		"data":      hex.EncodeToString(data),
	}
	if ts == 0 {
		return
	}
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(time.Now().Unix()/int64(ts)*int64(ts)))
	for i := 0; i < 8; i++ {
		data[i] ^= buf[i]
	}
	logger.WithFields(
		fields,
	).WithField(
		"after",
		hex.EncodeToString(data),
	).Debug("Done")
}

// Find tries to find peer's identity (that equals to MAC)
// by taking first blocksize sized bytes from data at the beginning
// as plaintext and last bytes as cyphertext.
func (mc *MACCache) Find(data []byte) (*PeerID, error) {
	const minimumSize = 8 * 2
	fields := logrus.Fields{
		"func": logFuncPrefix + "MACCache.Find",
		"data": len(data),
		"size": mc.Length(),
	}
	logger.WithFields(fields).Debug("Starting")
	if len(data) < minimumSize {
		return nil, errors.Errorf("MAC is too short %d, minimum %d", len(data), minimumSize)
	}
	buf := make([]byte, 8)
	sum := make([]byte, 32)
	mc.l.RLock()
	defer mc.l.RUnlock()
	for pid, mt := range mc.cache {
		loopFields := logrus.Fields{"pid": pid.String()}
		logger.WithFields(loopFields).Debug("Processing")
		copy(buf, data)
		AddTimeSync(mt.ts, buf)
		mt.l.Lock()
		mt.mac.Reset()
		logger.WithFields(
			fields,
		).WithField(
			"buf", hex.EncodeToString(buf),
		).Debug("mt.mac.Write")
		if _, err := mt.mac.Write(buf); err != nil {
			mt.l.Unlock()
			return nil, errors.Wrap(err, "mt.mac.Write")
		}
		logger.WithFields(
			fields,
		).WithField(
			"buf",
			hex.EncodeToString(buf[:0]),
		).Debug("mt.mac.Sum")
		mt.mac.Sum(sum[:0])
		mt.l.Unlock()

		if subtle.ConstantTimeCompare(sum[len(sum)-8:], data[len(data)-8:]) == 1 {
			logger.WithFields(fields).WithFields(loopFields).Debug("Matching peer")
			ppid := PeerID(pid)
			return &ppid, nil
		}

		logger.WithFields(fields).WithFields(loopFields).Debug("Peer is not matched")
	}
	logger.WithFields(fields).Debug("Can not find matching peer ID")
	return nil, nil
}
