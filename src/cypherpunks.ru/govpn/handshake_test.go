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
	"testing"
)

func testHandshake(t *testing.T, cl, srv *Handshake) {
	var err error
	if _, err = srv.Server(testCt); err != nil {
		t.Error(err)
	}
	if _, err = cl.Client(testCt); err != nil {
		t.Error(err)
	}
	p, err := srv.Server(testCt)
	if p == nil {
		t.Fail()
	}
	if err != nil {
		t.Error(err)
	}
	p, err = cl.Client(testCt)
	if p == nil {
		t.Fail()
	}
	if err != nil {
		t.Error(err)
	}
}

func TestHandshakeSymmetric(t *testing.T) {
	var err error
	// initial values are taken from peer_test.go's init()
	v := VerifierNew(1<<10, 1<<4, 1, &testPeerID)
	testConf.Verifier = v
	testConf.DSAPriv, err = v.PasswordApply("does not matter")
	if err != nil {
		t.Error(err)
	}
	hsS := NewHandshake("server", Dummy{&testCt}, testConf)
	hsC, err := HandshakeStart("client", Dummy{&testCt}, testConf)
	if err != nil {
		t.Error(err)
	}
	testHandshake(t, hsC, hsS)
}

func TestHandshakeNoiseSymmetric(t *testing.T) {
	var err error
	// initial values are taken from peer_test.go's init()
	v := VerifierNew(1<<10, 1<<4, 1, &testPeerID)
	testConf.Verifier = v
	testConf.DSAPriv, err = v.PasswordApply("does not matter")
	if err != nil {
		t.Error(err)
	}
	testConf.Noise = true
	hsS := NewHandshake("server", Dummy{&testCt}, testConf)
	hsC, err := HandshakeStart("client", Dummy{&testCt}, testConf)
	if err != nil {
		t.Error(err)
	}
	testHandshake(t, hsC, hsS)
	testConf.Noise = false
}

func TestHandshakeEnclessSymmetric(t *testing.T) {
	var err error
	// initial values are taken from peer_test.go's init()
	v := VerifierNew(1<<10, 1<<4, 1, &testPeerID)
	testConf.Verifier = v
	testConf.DSAPriv, err = v.PasswordApply("does not matter")
	if err != nil {
		t.Error(err)
	}
	testConf.Encless = true
	testConf.Noise = true
	hsS := NewHandshake("server", Dummy{&testCt}, testConf)
	hsC, err := HandshakeStart("client", Dummy{&testCt}, testConf)
	if err != nil {
		t.Error(err)
	}
	testHandshake(t, hsC, hsS)
	testConf.Encless = false
	testConf.Noise = false
}
