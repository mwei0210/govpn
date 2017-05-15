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
	"bytes"
	"encoding/base64"
	"fmt"
	"hash"
	"io/ioutil"
	"os"
	"strings"
	"syscall"

	"github.com/agl/ed25519"
	"github.com/pkg/errors"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/ssh/terminal"

	"cypherpunks.ru/balloon"
)

const (
	// DefaultS default Balloon space cost
	DefaultS = 1 << 20 / 32
	// DefaultT default Balloon time cost
	DefaultT = 1 << 4
	// DefaultP default Balloon number of job
	DefaultP = 2

	wrapDecodeString = "base64.RawStdEncoding.DecodeString"
)

// Verifier is used to authenticate a peer
type Verifier struct {
	S   int
	T   int
	P   int
	ID  *PeerID
	Pub *[ed25519.PublicKeySize]byte
}

// VerifierNew generates new verifier for given peer,
// with specified password and hashing parameters.
func VerifierNew(s, t, p int, id *PeerID) *Verifier {
	return &Verifier{S: s, T: t, P: p, ID: id}
}

// PasswordApply applies the password: create Ed25519 keypair based on it,
// saves public key in verifier.
func (v *Verifier) PasswordApply(password string) (*[ed25519.PrivateKeySize]byte, error) {
	// TODO: there is an extremely weird bug, "balloon.H" panic if I the `hash.Hash`
	// outside the "hasher" function.
	hasher := func() hash.Hash {
		nilHash, err := blake2b.New256(nil)
		// blake2b.New256 can't return an error if key is nil so if following should never executes
		// if it does happen, blake2b.New256 implementation changes, and this code should be updated.
		if err != nil {
			panic(err)
		}
		return nilHash
	}
	r := balloon.H(hasher, []byte(password), v.ID[:], v.S, v.T, v.P)

	defer SliceZero(r)
	src := bytes.NewBuffer(r)
	pub, prv, err := ed25519.GenerateKey(src)
	if err != nil {
		return nil, errors.Wrap(err, "ed25519.GenerateKey")
	}
	v.Pub = pub
	return prv, nil
}

// VerifierFromString parses either short or long verifier form.
func VerifierFromString(input string) (*Verifier, error) {
	ss := strings.Split(input, "$")
	if len(ss) < 4 || ss[1] != "balloon" {
		return nil, errors.New("Invalid verifier structure")
	}
	var s, t, p int
	n, err := fmt.Sscanf(ss[2], "s=%d,t=%d,p=%d", &s, &t, &p)
	if err != nil {
		return nil, errors.Wrap(err, "fmt.Sscanf")
	}
	if n != 3 {
		return nil, errors.New("Invalid verifier parameters")
	}
	salt, err := base64.RawStdEncoding.DecodeString(ss[3])
	if err != nil {
		return nil, errors.Wrap(err, wrapDecodeString)
	}
	v := Verifier{S: s, T: t, P: p}
	id := new([IDSize]byte)
	copy(id[:], salt)
	pid := PeerID(*id)
	v.ID = &pid
	if len(ss) == 5 {
		pub, err := base64.RawStdEncoding.DecodeString(ss[4])
		if err != nil {
			return nil, errors.Wrap(err, wrapDecodeString)
		}
		v.Pub = new([ed25519.PublicKeySize]byte)
		copy(v.Pub[:], pub)
	}
	return &v, nil
}

// ShortForm outputs the short verifier string form -- it is useful
// for the client. It does not include public key.
func (v *Verifier) ShortForm() string {
	return fmt.Sprintf(
		"$balloon$s=%d,t=%d,p=%d$%s",
		v.S, v.T, v.P, base64.RawStdEncoding.EncodeToString(v.ID[:]),
	)
}

// LongForm outputs long verifier string form -- it is useful for the server.
// It includes public key.
func (v *Verifier) LongForm() string {
	return fmt.Sprintf(
		"%s$%s", v.ShortForm(),
		base64.RawStdEncoding.EncodeToString(v.Pub[:]),
	)
}

// KeyRead reads the key either from text file (if path is specified), or
// from the terminal.
func KeyRead(path string) (string, error) {
	const (
		emptyString       = ""
		wrapOsStderrWrite = "os.Stderr.Write"
	)
	var p []byte
	var err error
	var pass string
	if path == emptyString {
		if _, err = os.Stderr.Write([]byte("Passphrase:")); err != nil {
			return emptyString, errors.Wrap(err, wrapOsStderrWrite)
		}
		p, err = terminal.ReadPassword(int(uintptr(syscall.Stdin)))
		if err != nil {
			return emptyString, errors.Wrap(err, "terminal.ReadPassword")
		}
		if _, err = os.Stderr.Write([]byte("\n")); err != nil {
			return emptyString, errors.Wrap(err, wrapOsStderrWrite)
		}
		pass = string(p)
	} else {
		if p, err = ioutil.ReadFile(path); err != nil {
			return emptyString, errors.Wrap(err, "ioutil.ReadFile")
		}
		pass = strings.TrimRight(string(p), "\n")
	}
	if len(pass) == 0 {
		return emptyString, errors.New("Empty passphrase submitted")
	}
	return pass, nil
}
