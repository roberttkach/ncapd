package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	ncapdpb "github.com/roberttkach/ncapd/proto"
)

type server struct {
	ncapdpb.UnimplementedProbeServiceServer
}

func (s *server) Submit(_ context.Context, req *ncapdpb.SubmitRequest) (*ncapdpb.SubmitResponse, error) {
	entry := map[string]any{
		"time":    time.Now().UTC().Format(time.RFC3339),
		"node_id": req.GetNodeId(),
		"count":   len(req.GetResults()),
		"results": req.GetResults(),
	}
	data, _ := json.Marshal(entry)

	f, err := os.OpenFile("/tmp/submits.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("failed to open log: %v", err)
	} else {
		fmt.Fprintln(f, string(data))
		f.Close()
	}

	log.Printf("submit: node_id=%q count=%d", req.GetNodeId(), len(req.GetResults()))
	return &ncapdpb.SubmitResponse{Success: true}, nil
}

func main() {
	certFile := os.Getenv("MOCK_GRPC_CERT")
	keyFile := os.Getenv("MOCK_GRPC_KEY")

	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	opts := []grpc.ServerOption{}
	if certFile != "" && keyFile != "" {
		creds, err := credentials.NewServerTLSFromFile(certFile, keyFile)
		if err != nil {
			log.Fatalf("failed to load TLS: %v", err)
		}
		opts = append(opts, grpc.Creds(creds))
		log.Println("mock-grpc: TLS enabled")
	} else {
		log.Println("mock-grpc: TLS disabled (plaintext)")
	}

	s := grpc.NewServer(opts...)
	ncapdpb.RegisterProbeServiceServer(s, &server{})

	log.Println("mock-grpc: listening on :50051")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
