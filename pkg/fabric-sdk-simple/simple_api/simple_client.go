/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0

@carrie, 2021-2-19, 1 file(s)
*/

package simple_api

import (
	"context"
	"fmt"
	"time"

	ab "github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/protos/orderer"
	pb "github.com/hyperledger/fabric-sdk-go/third_party/github.com/hyperledger/fabric/protos/peer"
	"github.com/pkg/errors"
)

type commonClient struct {
	*GRPCClient
	address string
	sn      string
}

// OrdererClient represents a client for communicating with an ordering
// service
type OrdererClient struct {
	commonClient
}

// PeerClient represents a client for communicating with a peer
type PeerClient struct {
	commonClient
}

func NewPeerClient(address string, caPEM []byte) (*PeerClient, error) {
	clientConfig := ClientConfig{Timeout: 3 * time.Second,
		SecOpts: &SecureOptions{UseTLS: true, ServerRootCAs: [][]byte{caPEM}}}
	gClient, err := NewGRPCClient(clientConfig)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to create PeerClient from config")
	}
	pClient := &PeerClient{
		commonClient: commonClient{
			GRPCClient: gClient,
			address:    address,
		}}
	return pClient, nil
}

// Deliver returns a client for the Deliver service
func (pc *PeerClient) Deliver() (pb.Deliver_DeliverClient, error) {
	conn, err := pc.commonClient.NewConnection(pc.address, pc.sn)
	if err != nil {
		return nil, errors.WithMessage(err, fmt.Sprintf("deliver client failed to connect to %s", pc.address))
	}
	return pb.NewDeliverClient(conn).Deliver(context.TODO())
}

// NewOrdererClient creates an instance of an OrdererClient from the
// global Viper instance
func NewOrdererClient(address string, caPEM []byte) (*OrdererClient, error) {
	clientConfig := ClientConfig{Timeout: 3 * time.Second,
		SecOpts: &SecureOptions{UseTLS: true, ServerRootCAs: [][]byte{caPEM}}}
	gClient, err := NewGRPCClient(clientConfig)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to create OrdererClient from config")
	}
	pClient := &OrdererClient{commonClient: commonClient{
		GRPCClient: gClient,
		address:    address,
	}}
	return pClient, nil
}

// Broadcast returns a broadcast client for the AtomicBroadcast service
func (oc *OrdererClient) Broadcast() (ab.AtomicBroadcast_BroadcastClient, error) {
	conn, err := oc.commonClient.NewConnection(oc.address, oc.sn)
	if err != nil {
		return nil, errors.WithMessage(err, fmt.Sprintf("orderer client failed to connect to %s", oc.address))
	}
	// TODO: check to see if we should actually handle error before returning
	return ab.NewAtomicBroadcastClient(conn).Broadcast(context.TODO())
}

// Deliver returns a deliver client for the AtomicBroadcast service
func (oc *OrdererClient) Deliver() (ab.AtomicBroadcast_DeliverClient, error) {
	conn, err := oc.commonClient.NewConnection(oc.address, oc.sn)
	if err != nil {
		return nil, errors.WithMessage(err, fmt.Sprintf("orderer client failed to connect to %s", oc.address))
	}
	// TODO: check to see if we should actually handle error before returning
	return ab.NewAtomicBroadcastClient(conn).Deliver(context.TODO())
}
