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

// Package aont stand for All-Or-Nothing-Transform, based on OAEP.
//
// This package implements OAEP (Optimal Asymmetric Encryption Padding)
// (http://cseweb.ucsd.edu/~mihir/papers/oaep.html)
// used there as All-Or-Nothing-Transformation
// (http://theory.lcs.mit.edu/~cis/pubs/rivest/fusion.ps).
// We do not fix OAEP parts length, instead we add hash-based
// checksum like in SAEP+
// (http://crypto.stanford.edu/~dabo/abstracts/saep.html).
//
// AONT takes 128-bit random r, data M to be encoded and produce the
// package PKG:
//
//     PKG = P1 || P2
//      P1 = ChaCha20(key=r, nonce=0x00, 0x00) XOR (M || BLAKE2b(r || M))
//      P2 = BLAKE2b(P1) XOR r
package aont

import (
	"crypto/subtle"

	"chacha20"
	"github.com/pkg/errors"
	"golang.org/x/crypto/blake2b"
)

const (
	// HSize TODO
	HSize = 32
	// RSize TODO
	RSize = 16

	wrapBlake2bNew256 = "blake2b.New256"
	wrapHashWrite     = "hash.Write"
)

var (
	dummyNonce = new([16]byte)
)

// Encode the data, produce AONT package. Data size will be larger than
// the original one for 48 bytes.
func Encode(r *[RSize]byte, in []byte) ([]byte, error) {
	out := make([]byte, len(in)+HSize+RSize)
	copy(out, in)
	h, err := blake2b.New256(nil)
	if err != nil {
		return nil, errors.Wrap(err, wrapBlake2bNew256)
	}
	if _, err = h.Write(r[:]); err != nil {
		return nil, errors.Wrap(err, wrapHashWrite)
	}
	if _, err = h.Write(in); err != nil {
		return nil, errors.Wrap(err, wrapHashWrite)
	}
	copy(out[len(in):], h.Sum(nil))
	chachaKey := new([32]byte)
	copy(chachaKey[:], r[:])
	chacha20.XORKeyStream(out, out, dummyNonce, chachaKey)
	h.Reset()
	if _, err = h.Write(out[:len(in)+32]); err != nil {
		return nil, errors.Wrap(err, wrapHashWrite)
	}
	for i, b := range h.Sum(nil)[:RSize] {
		out[len(in)+32+i] = b ^ r[i]
	}
	return out, nil
}

// Decode the data from AONT package. Data size will be smaller than the
// original one for 48 bytes.
func Decode(in []byte) ([]byte, error) {
	if len(in) < HSize+RSize {
		return nil, errors.New("Too small input buffer")
	}
	h, err := blake2b.New256(nil)
	if err != nil {
		return nil, errors.Wrap(err, wrapBlake2bNew256)
	}
	if _, err = h.Write(in[:len(in)-RSize]); err != nil {
		return nil, errors.Wrap(err, wrapHashWrite)
	}
	chachaKey := new([32]byte)
	for i, b := range h.Sum(nil)[:RSize] {
		chachaKey[i] = b ^ in[len(in)-RSize+i]
	}
	h.Reset()
	if _, err = h.Write(chachaKey[:RSize]); err != nil {
		return nil, errors.Wrap(err, wrapHashWrite)
	}
	out := make([]byte, len(in)-RSize)
	chacha20.XORKeyStream(out, in[:len(in)-RSize], dummyNonce, chachaKey)
	if _, err = h.Write(out[:len(out)-HSize]); err != nil {
		return nil, errors.Wrap(err, wrapHashWrite)
	}
	if subtle.ConstantTimeCompare(h.Sum(nil), out[len(out)-HSize:]) != 1 {
		return nil, errors.New("Invalid checksum")
	}
	return out[:len(out)-HSize], nil
}
