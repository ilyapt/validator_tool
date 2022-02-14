package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"github.com/golang/protobuf/proto"
	mspproto "github.com/hyperledger/fabric-protos-go/msp"
	"github.com/hyperledger/fabric/bccsp/utils"
	"github.com/hyperledger/fabric/msp"
	"math/big"
	"time"
)

type identity struct {
	mspId string
	cert *x509.Certificate
	pk *ecdsa.PublicKey
	sk *ecdsa.PrivateKey
}

func NewIdentity(mspId string, cert, key []byte) (*identity, error) {
	decoded, _ := pem.Decode(cert)
	parsed, err := x509.ParseCertificate(decoded.Bytes)
	if err != nil {
		return nil, err
	}

	privateKey, err := utils.PEMtoPrivateKey(key, nil)
	if err != nil {
		return nil, err
	}

	sk, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		panic("incorrect private key")
	}

	return &identity{
		mspId: mspId,
		cert: parsed,
		pk: parsed.PublicKey.(*ecdsa.PublicKey),
		sk: sk,
	}, nil
}

func (i *identity) ExpiresAt() time.Time {
	return i.cert.NotAfter
}

func (i *identity) GetIdentifier() *msp.IdentityIdentifier {
	return &msp.IdentityIdentifier{
		Mspid: i.mspId,
		Id: "client",
	}
}

func (i *identity) GetMSPIdentifier() string {
	return i.mspId
}

func (i *identity) Validate() error {
	return nil
}

func (i *identity) GetOrganizationalUnits() []*msp.OUIdentifier {
	return nil
}

func (i *identity) Anonymous() bool {
	return false
}

func (i *identity) Verify(msg []byte, sig []byte) error {
	digest := sha256.Sum256(msg)
	var esig struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(sig, &esig); err != nil {
		return err
	}
	if ecdsa.Verify(i.cert.PublicKey.(*ecdsa.PublicKey), digest[:], esig.R, esig.S) {
		return nil
	}
	return errors.New("incorrect signature")
}

func (i *identity) Serialize() ([]byte, error) {
	pemblock := &pem.Block{Type: "CERTIFICATE", Bytes: i.cert.Raw}
	pemBytes := pem.EncodeToMemory(pemblock)
	if pemBytes == nil {
		return nil, errors.New("encoding of identity failed")
	}

	creator := &mspproto.SerializedIdentity{Mspid: i.mspId, IdBytes: pemBytes}
	return proto.Marshal(creator)
}

func (i *identity) SatisfiesPrincipal(principal *mspproto.MSPPrincipal) error {
	return nil
}

func (i *identity) Sign(msg []byte) ([]byte, error) {
	digest := sha256.Sum256(msg)

	r, s, err := ecdsa.Sign(rand.Reader, i.sk, digest[:])
	if err != nil {
		return nil, err
	}

	s, err = utils.ToLowS(i.pk, s)
	if err != nil {
		return nil, err
	}

	return utils.MarshalECDSASignature(r, s)
}

func (i *identity) GetPublicVersion() msp.Identity {
	return i
}
