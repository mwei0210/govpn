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
	"encoding/binary"
	"io"
	"time"

	"chacha20"
	"github.com/Sirupsen/logrus"
	"github.com/agl/ed25519"
	"github.com/agl/ed25519/extra25519"
	"github.com/pkg/errors"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/curve25519"
)

const (
	// RSize TODO
	RSize = 8
	// SSize TODO
	SSize = 32

	wrapIDTag = "idTag id:%q timeSync:%d"
)

// Handshake is state of a handshake/negotiation between client and server
type Handshake struct {
	addr     string
	conn     io.Writer
	LastPing time.Time
	Conf     *PeerConf
	dsaPubH  *[ed25519.PublicKeySize]byte
	key      *[32]byte
	rNonce   *[16]byte
	dhPriv   *[32]byte    // own private DH key
	rServer  *[RSize]byte // random string for authentication
	rClient  *[RSize]byte
	sServer  *[SSize]byte // secret string for main key calculation
	sClient  *[SSize]byte
}

// LogFields return a logrus compatible logging context
func (h *Handshake) LogFields() logrus.Fields {
	const prefix = "hs_"
	return logrus.Fields{
		prefix + "remote":    h.addr,
		prefix + "last_ping": h.LastPing.String(),
		prefix + "id":        h.Conf.ID.String(),
	}
}

func keyFromSecrets(server, client []byte) *[SSize]byte {
	k := new([SSize]byte)
	for i := 0; i < SSize; i++ {
		k[i] = server[i] ^ client[i]
	}
	return k
}

// Zero handshake's memory state
func (h *Handshake) Zero() {
	if h.rNonce != nil {
		SliceZero(h.rNonce[:])
	}
	if h.dhPriv != nil {
		SliceZero(h.dhPriv[:])
	}
	if h.key != nil {
		SliceZero(h.key[:])
	}
	if h.dsaPubH != nil {
		SliceZero(h.dsaPubH[:])
	}
	if h.rServer != nil {
		SliceZero(h.rServer[:])
	}
	if h.rClient != nil {
		SliceZero(h.rClient[:])
	}
	if h.sServer != nil {
		SliceZero(h.sServer[:])
	}
	if h.sClient != nil {
		SliceZero(h.sClient[:])
	}
}

func (h *Handshake) rNonceNext(count uint64) *[16]byte {
	nonce := new([16]byte)
	nonceCurrent, _ := binary.Uvarint(h.rNonce[8:])
	binary.PutUvarint(nonce[8:], nonceCurrent+count)
	return nonce
}

func dhKeypairGen() (*[32]byte, *[32]byte, error) {
	priv := new([32]byte)
	pub := new([32]byte)
	repr := new([32]byte)
	reprFound := false
	for !reprFound {
		if _, err := io.ReadFull(Rand, priv[:]); err != nil {
			return nil, nil, errors.Wrapf(err, wrapIoReadFull, "Rand")
		}
		reprFound = extra25519.ScalarBaseMult(pub, repr, priv)
	}
	return priv, repr, nil
}

func dhKeyGen(priv, pub *[32]byte) *[32]byte {
	key := new([32]byte)
	curve25519.ScalarMult(key, priv, pub)
	hashed := blake2b.Sum256(key[:])
	return &hashed
}

// NewHandshake create new handshake state.
func NewHandshake(addr string, conn io.Writer, conf *PeerConf) *Handshake {
	state := Handshake{
		addr:     addr,
		conn:     conn,
		LastPing: time.Now(),
		Conf:     conf,
	}
	state.dsaPubH = new([ed25519.PublicKeySize]byte)
	copy(state.dsaPubH[:], state.Conf.Verifier.Pub[:])
	hashed := blake2b.Sum256(state.dsaPubH[:])
	state.dsaPubH = &hashed
	return &state
}

// Generate ID tag from client identification and data.
func idTag(id *PeerID, timeSync int, data []byte) ([]byte, error) {
	enc := make([]byte, 8)
	copy(enc, data)
	AddTimeSync(timeSync, enc)
	mac, err := blake2b.New256(id[:])
	if err != nil {
		return nil, errors.Wrap(err, wrapBlake2bNew256)
	}
	if _, err = mac.Write(enc); err != nil {
		return nil, errors.Wrap(err, "mac.Write")
	}
	sum := mac.Sum(nil)
	return sum[len(sum)-8:], nil
}

// HandshakeStart start handshake's procedure from the client. It is the entry point
// for starting the handshake procedure.
// First handshake packet will be sent immediately.
func HandshakeStart(addr string, conn io.Writer, conf *PeerConf) (*Handshake, error) {
	state := NewHandshake(addr, conn, conf)
	var (
		dhPubRepr *[32]byte
		err       error
	)
	if state.dhPriv, dhPubRepr, err = dhKeypairGen(); err != nil {
		return nil, errors.Wrap(err, "dhKeypairGen")
	}

	state.rNonce = new([16]byte)
	if _, err := io.ReadFull(Rand, state.rNonce[8:]); err != nil {
		return nil, errors.Wrapf(err, wrapIoReadFull, "Rand")
	}
	var enc []byte
	if conf.Noise {
		enc = make([]byte, conf.MTU-8-RSize)
	} else {
		enc = make([]byte, 32)
	}
	copy(enc, dhPubRepr[:])
	if conf.Encless {
		enc, err = EnclessEncode(state.dsaPubH, state.rNonce, enc)
		if err != err {
			return nil, errors.Wrap(err, wrapEnclessDecode)
		}
	} else {
		chacha20.XORKeyStream(enc, enc, state.rNonce, state.dsaPubH)
	}
	tag, err := idTag(state.Conf.ID, state.Conf.TimeSync, state.rNonce[8:])
	if err != nil {
		return nil, errors.Wrapf(err, wrapIDTag, state.Conf.ID.String(), state.Conf.TimeSync)
	}
	data := append(state.rNonce[8:], enc...)
	data = append(data, tag...)
	if _, err = state.conn.Write(data); err != nil {
		return nil, errors.Wrap(err, "state.conn.Write")
	}
	return state, nil
}

// Server process handshake message on the server side.
// This function is intended to be called on server's side.
// If this is the final handshake message, then new Peer object
// will be created and used as a transport.
func (h *Handshake) Server(data []byte) (*Peer, error) {
	// R + ENC(H(DSAPub), R, El(CDHPub)) + IDtag
	if h.rNonce == nil && ((!h.Conf.Encless && len(data) >= 48) ||
		(h.Conf.Encless && len(data) == EnclessEnlargeSize+h.Conf.MTU)) {
		h.rNonce = new([16]byte)
		copy(h.rNonce[8:], data[:RSize])

		// Decrypt remote public key
		cDHRepr := new([32]byte)
		if h.Conf.Encless {
			out, err := EnclessDecode(
				h.dsaPubH,
				h.rNonce,
				data[RSize:len(data)-8],
			)
			if err != nil {
				return nil, errors.Wrap(err, wrapEnclessDecode)
			}
			copy(cDHRepr[:], out)
		} else {
			chacha20.XORKeyStream(cDHRepr[:], data[RSize:RSize+32], h.rNonce, h.dsaPubH)
		}

		// Generate DH keypair
		var dhPubRepr *[32]byte
		var err error
		if h.dhPriv, dhPubRepr, err = dhKeypairGen(); err != nil {
			return nil, errors.Wrap(err, "dhKeypairGen")
		}

		// Compute shared key
		cDH := new([32]byte)
		extra25519.RepresentativeToPublicKey(cDH, cDHRepr)
		h.key = dhKeyGen(h.dhPriv, cDH)

		var encPub []byte
		if h.Conf.Encless {
			encPub = make([]byte, h.Conf.MTU)
			copy(encPub, dhPubRepr[:])
			encPub, err = EnclessEncode(h.dsaPubH, h.rNonceNext(1), encPub)
			if err != nil {
				return nil, errors.Wrap(err, wrapEnclessEncode)
			}
		} else {
			encPub = make([]byte, 32)
			chacha20.XORKeyStream(encPub, dhPubRepr[:], h.rNonceNext(1), h.dsaPubH)
		}

		// Generate R* and encrypt them
		h.rServer = new([RSize]byte)
		if _, err = io.ReadFull(Rand, h.rServer[:]); err != nil {
			return nil, errors.Wrapf(err, wrapIoReadFull, "Rand")
		}
		h.sServer = new([SSize]byte)
		if _, err = io.ReadFull(Rand, h.sServer[:]); err != nil {
			return nil, errors.Wrapf(err, wrapIoReadFull, "Rand")
		}
		var encRs []byte
		if h.Conf.Noise && !h.Conf.Encless {
			encRs = make([]byte, h.Conf.MTU-len(encPub)-8)
		} else if h.Conf.Encless {
			encRs = make([]byte, h.Conf.MTU-8)
		} else {
			encRs = make([]byte, RSize+SSize)
		}
		copy(encRs, append(h.rServer[:], h.sServer[:]...))
		if h.Conf.Encless {
			encRs, err = EnclessEncode(h.key, h.rNonce, encRs)
			if err != nil {
				return nil, errors.Wrap(err, wrapEnclessEncode)
			}
		} else {
			chacha20.XORKeyStream(encRs, encRs, h.rNonce, h.key)
		}

		tag, err := idTag(h.Conf.ID, h.Conf.TimeSync, encPub)
		if err != nil {
			return nil, errors.Wrapf(err, wrapIDTag, h.Conf.ID.String(), h.Conf.TimeSync)
		}

		// Send that to client
		_, err = h.conn.Write(append(encPub, append(
			encRs, tag...,
		)...))
		if err != nil {
			return nil, errors.Wrap(err, "conn.Write")
		}
		h.LastPing = time.Now()
	} else
	// ENC(K, R+1, RS + RC + SC + Sign(DSAPriv, K)) + IDtag
	if h.rClient == nil && ((!h.Conf.Encless && len(data) >= 120) ||
		(h.Conf.Encless && len(data) == EnclessEnlargeSize+h.Conf.MTU)) {
		var dec []byte
		var err error
		if h.Conf.Encless {
			dec, err = EnclessDecode(
				h.key,
				h.rNonceNext(1),
				data[:len(data)-8],
			)
			if err != nil {
				return nil, errors.Wrap(err, wrapEnclessDecode)
			}
			dec = dec[:RSize+RSize+SSize+ed25519.SignatureSize]
		} else {
			dec = make([]byte, RSize+RSize+SSize+ed25519.SignatureSize)
			chacha20.XORKeyStream(
				dec,
				data[:RSize+RSize+SSize+ed25519.SignatureSize],
				h.rNonceNext(1),
				h.key,
			)
		}
		if subtle.ConstantTimeCompare(dec[:RSize], h.rServer[:]) != 1 {
			return nil, errors.New("Invalid server's random number")
		}
		sign := new([ed25519.SignatureSize]byte)
		copy(sign[:], dec[RSize+RSize+SSize:])
		if !ed25519.Verify(h.Conf.Verifier.Pub, h.key[:], sign) {
			return nil, errors.New("Invalid signature")
		}

		// Send final answer to client
		var enc []byte
		if h.Conf.Noise {
			enc = make([]byte, h.Conf.MTU-8)
		} else {
			enc = make([]byte, RSize)
		}
		copy(enc, dec[RSize:RSize+RSize])
		if h.Conf.Encless {
			enc, err = EnclessEncode(h.key, h.rNonceNext(2), enc)
			if err != nil {
				return nil, errors.Wrap(err, wrapEnclessEncode)
			}
		} else {
			chacha20.XORKeyStream(enc, enc, h.rNonceNext(2), h.key)
		}
		tag, err := idTag(h.Conf.ID, h.Conf.TimeSync, enc)
		if err != nil {
			return nil, errors.Wrapf(err, wrapIDTag, h.Conf.ID.String(), h.Conf.TimeSync)
		}
		if _, err = h.conn.Write(append(enc, tag...)); err != nil {
			return nil, errors.Wrap(err, "conn.Write")
		}

		// Switch peer
		peer, err := newPeer(
			false,
			h.addr,
			h.conn,
			h.Conf,
			keyFromSecrets(h.sServer[:], dec[RSize+RSize:RSize+RSize+SSize]))
		if err != nil {
			return nil, errors.Wrap(err, "newPeer")
		}
		h.LastPing = time.Now()
		return peer, nil
	}
	return nil, nil
}

// Client process handshake message on the client side.
// This function is intended to be called on client's side.
// If this is the final handshake message, then new Peer object
// will be created and used as a transport. If no mutually
// authenticated Peer is ready, then return nil.
func (h *Handshake) Client(data []byte) (*Peer, error) {
	// ENC(H(DSAPub), R+1, El(SDHPub)) + ENC(K, R, RS + SS) + IDtag
	if h.rServer == nil && h.key == nil &&
		((!h.Conf.Encless && len(data) >= 80) ||
			(h.Conf.Encless && len(data) == 2*(EnclessEnlargeSize+h.Conf.MTU))) {
		// Decrypt remote public key
		sDHRepr := new([32]byte)
		var tmp []byte
		var err error
		if h.Conf.Encless {
			tmp, err = EnclessDecode(
				h.dsaPubH,
				h.rNonceNext(1),
				data[:len(data)/2],
			)
			if err != nil {
				return nil, errors.Wrap(err, wrapEnclessDecode)
			}
			copy(sDHRepr[:], tmp[:32])
		} else {
			chacha20.XORKeyStream(sDHRepr[:], data[:32], h.rNonceNext(1), h.dsaPubH)
		}

		// Compute shared key
		sDH := new([32]byte)
		extra25519.RepresentativeToPublicKey(sDH, sDHRepr)
		h.key = dhKeyGen(h.dhPriv, sDH)

		// Decrypt Rs
		h.rServer = new([RSize]byte)
		h.sServer = new([SSize]byte)
		if h.Conf.Encless {
			tmp, err = EnclessDecode(h.key, h.rNonce, data[len(data)/2:len(data)-8])
			if err != nil {
				return nil, errors.Wrap(err, wrapEnclessDecode)
			}
			copy(h.rServer[:], tmp[:RSize])
			copy(h.sServer[:], tmp[RSize:RSize+SSize])
		} else {
			decRs := make([]byte, RSize+SSize)
			chacha20.XORKeyStream(decRs, data[SSize:SSize+RSize+SSize], h.rNonce, h.key)
			copy(h.rServer[:], decRs[:RSize])
			copy(h.sServer[:], decRs[RSize:])
		}

		// Generate R* and signature and encrypt them
		h.rClient = new([RSize]byte)
		if _, err = io.ReadFull(Rand, h.rClient[:]); err != nil {
			return nil, errors.Wrapf(err, wrapIoReadFull, "Rand")
		}
		h.sClient = new([SSize]byte)
		if _, err = io.ReadFull(Rand, h.sClient[:]); err != nil {
			return nil, errors.Wrapf(err, wrapIoReadFull, "Rand")
		}
		sign := ed25519.Sign(h.Conf.DSAPriv, h.key[:])

		var enc []byte
		if h.Conf.Noise {
			enc = make([]byte, h.Conf.MTU-8)
		} else {
			enc = make([]byte, RSize+RSize+SSize+ed25519.SignatureSize)
		}
		copy(enc, h.rServer[:])
		copy(enc[RSize:], h.rClient[:])
		copy(enc[RSize+RSize:], h.sClient[:])
		copy(enc[RSize+RSize+SSize:], sign[:])
		if h.Conf.Encless {
			enc, err = EnclessEncode(h.key, h.rNonceNext(1), enc)
			if err != nil {
				return nil, errors.Wrap(err, wrapEnclessEncode)
			}
		} else {
			chacha20.XORKeyStream(enc, enc, h.rNonceNext(1), h.key)
		}

		tag, err := idTag(h.Conf.ID, h.Conf.TimeSync, enc)
		if err != nil {
			return nil, errors.Wrapf(err, wrapIDTag, h.Conf.ID.String(), h.Conf.TimeSync)
		}

		// Send that to server
		if _, err = h.conn.Write(append(enc, tag...)); err != nil {
			return nil, errors.Wrap(err, "conn.Write")
		}
		h.LastPing = time.Now()
	} else
	// ENC(K, R+2, RC) + IDtag
	if h.key != nil && ((!h.Conf.Encless && len(data) >= 16) ||
		(h.Conf.Encless && len(data) == EnclessEnlargeSize+h.Conf.MTU)) {
		var err error
		// Decrypt rClient
		var dec []byte
		if h.Conf.Encless {
			dec, err = EnclessDecode(h.key, h.rNonceNext(2), data[:len(data)-8])
			if err != nil {
				return nil, errors.Wrap(err, wrapEnclessDecode)
			}
			dec = dec[:RSize]
		} else {
			dec = make([]byte, RSize)
			chacha20.XORKeyStream(dec, data[:RSize], h.rNonceNext(2), h.key)
		}
		if subtle.ConstantTimeCompare(dec, h.rClient[:]) != 1 {
			return nil, errors.New("Invalid client's random number")
		}

		// Switch peer
		peer, err := newPeer(
			true,
			h.addr,
			h.conn,
			h.Conf,
			keyFromSecrets(h.sServer[:], h.sClient[:]),
		)
		if err != nil {
			return nil, errors.Wrap(err, "newPeer")
		}
		h.LastPing = time.Now()
		return peer, nil
	}

	// no peer yet, no error
	return nil, nil
}
