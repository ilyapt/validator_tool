package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-protos-go/common"
	pb "github.com/hyperledger/fabric-protos-go/peer"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/spf13/pflag"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"time"
)

const (
	DefaultMaxRecvMsgSize = 100 * 1024 * 1024
	DefaultMaxSendMsgSize = 100 * 1024 * 1024
	DefaultTimeout = 30 * time.Second

	StatePrefixEmission = "61"
)

func main() {
	cert := pflag.String("cert", "./cert.pem", "path to certificate")
	key := pflag.String("key", "./cert.key", "path to private key")
	ca := pflag.String("ca", "./ca.pem", "path root certificate")
	msp := pflag.String("msp", "neoMSP", "msp ID")
	peer := pflag.String("peer", "", "peer address with port")
	token := pflag.String("token", "", "token (channel/chaincode) name")
	pflag.Parse()

	certData, err := ioutil.ReadFile(*cert)
	if err != nil {
		log.Fatal(err)
	}
	keyData, err := ioutil.ReadFile(*key)
	if err != nil {
		log.Fatal(err)
	}

	tlsCert, err := tls.X509KeyPair(certData, keyData)
	if err != nil {
		log.Fatal(err)
	}

	caData, err := ioutil.ReadFile(*ca)
	block, _ := pem.Decode(caData)
	if block == nil {
		log.Fatal("couldn't parse CA certificate")
	}
	parsedCa, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	caPool := x509.NewCertPool()
	caPool.AddCert(parsedCa)

	dialOpts := []grpc.DialOption{
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time: time.Duration(1) * time.Minute,
			Timeout: time.Duration(20) * time.Second,
			PermitWithoutStream: true,
		}),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(DefaultMaxRecvMsgSize),
			grpc.MaxCallSendMsgSize(DefaultMaxSendMsgSize),
		),
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			MinVersion:  tls.VersionTLS12,
			RootCAs:     caPool,
			Certificates: []tls.Certificate{ tlsCert },
		})),
	}

	ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeout)
	defer cancel()

	conn, err := grpc.DialContext(ctx, *peer, dialOpts...)
	if err != nil {
		log.Fatal(err)
	}

	identity, err := NewIdentity(*msp, certData, keyData)
	if err != nil {
		log.Fatal(err)
	}

	info, err := getInfo(identity, conn, *token)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("current height %d last block hash %s", info.Height, hex.EncodeToString(info.CurrentBlockHash))

	blockHash := info.CurrentBlockHash
	//blockHash, err = hex.DecodeString("03eeb963775780bad46e38d99e48db548db0fac1a2473e7e2d53fbbd7498044c")
	//if err != nil {
	//	panic(err)
	//}
	for {
		block, err := getBlock(identity, conn, *token, blockHash)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Print("\033[G\033[K")
		fmt.Print("processing block ", block.Header.Number)
		blockHash = block.Header.PreviousHash

		codes := block.Metadata.Metadata[common.BlockMetadataIndex_TRANSACTIONS_FILTER]
		l := len(block.Data.Data) - 1
		for i := range block.Data.Data {
			j := l-i
			if pb.TxValidationCode(codes[j]) != pb.TxValidationCode_VALID {
				continue
			}
			header, writes, err := parseTransaction(block.Data.Data[j], *token)
			if err != nil {
				log.Fatal(err)
			}
			if writes == nil {
				continue
			}
			for _, w := range writes {
				if w.Key == StatePrefixEmission {
					fmt.Print("\n")
					log.Printf("tx %s (timestamp %s, block %d) changed total supply to %s",
						header.TxId, header.Timestamp.AsTime().String(),
						block.Header.Number, new(big.Int).SetBytes(w.Value))
					os.Exit(0)
				}
			}
		}
	}
	fmt.Print("\n")
}

func getInfo(signer *identity, conn *grpc.ClientConn, channel string) (*common.BlockchainInfo, error) {
	spec := &pb.ChaincodeInvocationSpec{
		ChaincodeSpec: &pb.ChaincodeSpec{
			ChaincodeId: &pb.ChaincodeID{Name: "qscc"},
			Input:       &pb.ChaincodeInput{Args: [][]byte{
				[]byte("GetChainInfo"),
				[]byte(channel),
			}},
		},
	}

	resp, err := query(signer, conn, spec, channel)
	if err != nil {
		return nil, err
	}

	var info common.BlockchainInfo
	if err := proto.Unmarshal(resp.Response.Payload, &info); err != nil {
		return nil, err
	}

	return &info, nil
}

func query(signer *identity, conn *grpc.ClientConn, spec *pb.ChaincodeInvocationSpec, channel string) (*pb.ProposalResponse, error){
	serializedSigner, err := signer.Serialize()
	if err != nil {
		return nil, err
	}

	proposal, _, err := protoutil.CreateChaincodeProposal(common.HeaderType_ENDORSER_TRANSACTION, channel, spec, serializedSigner)
	if err != nil {
		return nil, err
	}

	signedProposal, err := protoutil.GetSignedProposal(proposal, signer)
	if err != nil {
		return nil, err
	}

	endorser := pb.NewEndorserClient(conn)
	return endorser.ProcessProposal(context.Background(), signedProposal)
}

func getBlock(signer *identity, conn *grpc.ClientConn, channel string, hash []byte) (*common.Block, error) {
	spec := &pb.ChaincodeInvocationSpec{
		ChaincodeSpec: &pb.ChaincodeSpec{
			ChaincodeId: &pb.ChaincodeID{Name: "qscc"},
			Input:       &pb.ChaincodeInput{Args: [][]byte{
				[]byte("GetBlockByHash"),
				[]byte(channel),
				hash,
			}},
		},
	}

	resp, err := query(signer, conn, spec, channel)
	if err != nil {
		return nil, err
	}

	var block common.Block
	if err = proto.Unmarshal(resp.Response.Payload, &block); err != nil {
		return nil, err
	}

	return &block, nil
}