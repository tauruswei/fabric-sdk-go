/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0

@carrie, 2021-2-19, 1 file(s)
*/

package simple_api

import (
	"crypto/rand"
	"strings"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes/timestamp"
	ab "github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/protos/orderer"
	cb "github.com/hyperledger/fabric-sdk-go/third_party/github.com/hyperledger/fabric/protos/common"
	pb "github.com/hyperledger/fabric-sdk-go/third_party/github.com/hyperledger/fabric/protos/peer"
	"github.com/pkg/errors"
)

type Migrate struct {
	Status int32 `protobuf:"varint,1,opt,name=status,proto3" json:"status,omitempty"`
	// Info string which may contain additional information about the status returned
	Info    string `protobuf:"bytes,2,opt,name=info,proto3" json:"info,omitempty"`
	Prefix  string `protobuf:"bytes,3,opt,name=prefix,proto3" json:"prefix,omitempty"`
	Node    string `protobuf:"bytes,4,opt,name=node,proto3" json:"node,omitempty"`
	Channel string `protobuf:"bytes,5,opt,name=channel,json=channel,proto3" json:"channel,omitempty"`
	Nfsdir  string `protobuf:"bytes,6,opt,name=nfsdir,json=nfsdir,proto3" json:"nfsdir,omitempty"`
	Before  string `protobuf:"bytes,7,opt,name=before,json=before,proto3" json:"before,omitempty"`
}

func (m *Migrate) Reset()         { *m = Migrate{} }
func (m *Migrate) String() string { return proto.CompactTextString(m) }
func (*Migrate) ProtoMessage()    {}

// GetEnvelopeFromBlock gets an envelope from a block's Data field.
func GetMigrateFromBlock(data []byte) (*Migrate, error) {
	// Block always begins with an envelope
	var err error
	migrate := &Migrate{}
	if err = proto.Unmarshal(data, migrate); err != nil {
		return nil, errors.Wrap(err, "error unmarshaling Envelope")
	}

	return migrate, nil
}

func MakeEnvelope(prefix, node, channel, nfsdir, before string) *cb.Envelope {
	channelHeader := &cb.ChannelHeader{
		Type:    int32(88041112),
		Version: 1,
		Timestamp: &timestamp.Timestamp{
			Seconds: time.Now().Unix(),
			Nanos:   0,
		},
		ChannelId: channel,
		Epoch:     0,
	}
	signatureHeader := &cb.SignatureHeader{
		Nonce: CreateNonceOrPanic(),
	}
	header := &cb.Header{
		ChannelHeader:   MarshalOrPanic(channelHeader),
		SignatureHeader: MarshalOrPanic(signatureHeader),
	}
	migrate := &Migrate{Prefix: prefix, Node: node, Channel: channel, Nfsdir: nfsdir, Before: before}
	payload := &cb.Payload{Header: header, Data: MarshalOrPanic(migrate)}
	envelope := &cb.Envelope{Payload: MarshalOrPanic(payload)}
	return envelope
}

// MarshalOrPanic serializes a protobuf message and panics if this
// operation fails
func MarshalOrPanic(pb proto.Message) []byte {
	data, err := proto.Marshal(pb)
	if err != nil {
		panic(err)
	}
	return data
}

// CreateNonceOrPanic generates a nonce using the common/crypto package
// and panics if this operation fails.
func CreateNonceOrPanic() []byte {
	nonce, err := CreateNonce()
	if err != nil {
		panic(err)
	}
	return nonce
}

// CreateNonce generates a nonce using the common/crypto package.
func CreateNonce() ([]byte, error) {
	nonce, err := getRandomNonce()
	return nonce, errors.WithMessage(err, "error generating random nonce")
}

func getRandomNonce() ([]byte, error) {
	key := make([]byte, 24)

	_, err := rand.Read(key)
	if err != nil {
		return nil, errors.Wrap(err, "error getting random bytes")
	}
	return key, nil
}

func Send2Peer(client *PeerClient, envelope *cb.Envelope) (*Migrate, error) {
	deliver, err := client.Deliver()
	if err != nil {
		return nil, err
	}
	err = deliver.Send(envelope)
	if err != nil {
		return nil, err
	}
	msg, err := deliver.Recv()
	if err != nil {
		return nil, errors.Wrap(err, "error receiving")
	}

	switch t := msg.Type.(type) {
	case *pb.DeliverResponse_Status:
		return nil, errors.Errorf("can't read the block: %v", t)
	case *pb.DeliverResponse_Block:
		deliver.Recv() // Flush the success message
		return GetMigrateFromBlock(t.Block.Data.Data[0])
	default:
		return nil, errors.Errorf("response error: unknown type %T", t)
	}
}

func Send2Orderer(client *OrdererClient, envelope *cb.Envelope) (*Migrate, error) {
	deliver, err := client.Deliver()
	if err != nil {
		return nil, err
	}
	err = deliver.Send(envelope)
	if err != nil {
		return nil, err
	}
	msg, err := deliver.Recv()
	if err != nil {
		return nil, errors.Wrap(err, "error receiving")
	}

	switch t := msg.Type.(type) {
	case *ab.DeliverResponse_Status:
		return nil, errors.Errorf("can't read the block: %v", t)
	case *ab.DeliverResponse_Block:
		deliver.Recv() // Flush the success message
		return GetMigrateFromBlock(t.Block.Data.Data[0])
	default:
		return nil, errors.Errorf("response error: unknown type %T", t)
	}
}

func ChannelMigrate(prefix, node, channel, nfs, before string, tls []byte) (*Migrate, error) {
	envelope := MakeEnvelope(prefix, node, channel, nfs, before)

	var err error
	if strings.EqualFold(prefix, "peer") {
		client, ret := NewPeerClient(node, tls)
		if err == nil {
			return Send2Peer(client, envelope)
		}
		err = ret
	} else if strings.EqualFold(prefix, "orderer") {
		client, ret := NewOrdererClient(node, tls)
		if ret == nil {
			return Send2Orderer(client, envelope)
		}
		err = ret
	}

	return nil, err
}
