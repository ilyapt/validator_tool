package main

import (
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-protos-go/ledger/rwset"
	"github.com/hyperledger/fabric-protos-go/ledger/rwset/kvrwset"
	pb "github.com/hyperledger/fabric-protos-go/peer"
)

func parseTransaction(data []byte, channel string) (*common.ChannelHeader, []*kvrwset.KVWrite, error) {
	var envelope common.Envelope
	if err := proto.Unmarshal(data, &envelope); err != nil {
		return nil, nil, err
	}

	payload := &common.Payload{}
	if err := proto.Unmarshal(envelope.Payload, payload); err != nil {
		return nil, nil, err
	}

	header := &common.ChannelHeader{}
	if err := proto.Unmarshal(payload.Header.ChannelHeader, header); err != nil {
		return nil, nil, err
	}

	if header.Type != int32(common.HeaderType_ENDORSER_TRANSACTION) {
		return nil, nil, nil
	}

	transaction := &pb.Transaction{}
	if err := proto.Unmarshal(payload.Data, transaction); err != nil {
		return nil, nil, err
	}

	ccActionPayload := &pb.ChaincodeActionPayload{}
	if err := proto.Unmarshal(transaction.Actions[0].Payload, ccActionPayload); err != nil {
		return nil, nil, err
	}

	proposalResponsePayload := &pb.ProposalResponsePayload{}
	if err := proto.Unmarshal(ccActionPayload.Action.ProposalResponsePayload, proposalResponsePayload); err != nil {
		return nil, nil, err
	}

	ccAction := &pb.ChaincodeAction{}
	if err := proto.Unmarshal(proposalResponsePayload.Extension, ccAction); err != nil {
		return nil, nil, err
	}

	ccProposalPayload := &pb.ChaincodeProposalPayload{}
	if err := proto.Unmarshal(ccActionPayload.ChaincodeProposalPayload, ccProposalPayload); err != nil {
		return nil, nil, err
	}

	input := &pb.ChaincodeInvocationSpec{}
	if err := proto.Unmarshal(ccProposalPayload.Input, input); err != nil {
		return nil, nil, err
	}

	txReadWriteSet := &rwset.TxReadWriteSet{}
	if err := proto.Unmarshal(ccAction.Results, txReadWriteSet); err != nil {
		return nil, nil, err
	}

	for _, rwSet := range txReadWriteSet.NsRwset {
		if rwSet.Namespace != channel {
			continue
		}

		var kvRwSet kvrwset.KVRWSet
		if err := proto.Unmarshal(rwSet.Rwset, &kvRwSet); err != nil {
			return nil, nil, err
		}

		return header, kvRwSet.Writes, nil
	}

	return nil, nil, nil
}
