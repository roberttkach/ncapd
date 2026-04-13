package master

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/roberttkach/ncapd/internal/core"
	ncapdpb "github.com/roberttkach/ncapd/proto"
)

type Client struct {
	conn   *grpc.ClientConn
	client ncapdpb.ProbeServiceClient
	log    *zap.Logger
	nodeID string
}

type TLSConfig struct {
	Enabled            bool
	InsecureSkipVerify bool
	CAFile             string
	CertFile           string
	KeyFile            string
}

func New(ctx context.Context, addr, nodeID string, tlsCfg *TLSConfig, log *zap.Logger) (*Client, error) {
	transportCreds := insecure.NewCredentials()
	if tlsCfg != nil {
		var err error
		transportCreds, err = tlsCfg.buildCredentials()
		if err != nil {
			return nil, fmt.Errorf("grpc: build TLS credentials: %w", err)
		}
	}

	conn, err := grpc.DialContext(ctx, addr, grpc.WithTransportCredentials(transportCreds))
	if err != nil {
		return nil, fmt.Errorf("grpc: dial: %w", err)
	}

	return &Client{
		conn:   conn,
		client: ncapdpb.NewProbeServiceClient(conn),
		nodeID: nodeID,
		log:    log,
	}, nil
}

func (c *Client) Submit(ctx context.Context, result core.Result) error {
	if c.nodeID == "" {
		return nil
	}
	batch := toProtoBatch(c.nodeID, []core.Result{result})
	submitCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	_, err := c.submit(submitCtx, batch)
	if err != nil {
		c.log.Debug("master submit failed",
			zap.String("check_id", result.ID),
			zap.Error(err))
	}
	return err
}

func (c *Client) SubmitBatch(ctx context.Context, results []core.Result) error {
	if c.nodeID == "" || len(results) == 0 {
		return nil
	}
	batch := toProtoBatch(c.nodeID, results)
	submitCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	_, err := c.submit(submitCtx, batch)
	if err != nil {
		c.log.Debug("master batch submit failed",
			zap.Int("count", len(results)),
			zap.Error(err))
	}
	return err
}

func (c *Client) Close() error {
	if c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

func (c *Client) submit(ctx context.Context, req *ncapdpb.SubmitRequest) (*ncapdpb.SubmitResponse, error) {
	resp, err := c.client.Submit(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("grpc: submit probe results: %w", err)
	}
	if !resp.GetSuccess() {
		return resp, fmt.Errorf("grpc: master rejected batch: %s", resp.GetError())
	}
	return resp, nil
}

func toProtoResult(r core.Result) *ncapdpb.ProbeResult {
	var ts *timestamppb.Timestamp
	if !r.At.IsZero() {
		ts = timestamppb.New(r.At)
	}

	return &ncapdpb.ProbeResult{
		Id:         r.ID,
		Type:       string(r.Type),
		TargetHost: r.Host,

		Status: string(r.Status),
		At:     ts,

		LatencyNs:     r.Latency.Nanoseconds(),
		ThroughputBps: r.Throughput,

		Detail: r.Detail,
		Error:  r.Err,
	}
}

func toProtoBatch(nodeID string, results []core.Result) *ncapdpb.SubmitRequest {
	if len(results) == 0 {
		return &ncapdpb.SubmitRequest{
			NodeId:  nodeID,
			Results: nil,
		}
	}

	protoResults := make([]*ncapdpb.ProbeResult, 0, len(results))
	for _, r := range results {
		if r.ID == "" {
			continue
		}
		protoResults = append(protoResults, toProtoResult(r))
	}

	return &ncapdpb.SubmitRequest{
		NodeId:  nodeID,
		Results: protoResults,
	}
}

func (c *TLSConfig) buildCredentials() (credentials.TransportCredentials, error) {
	if !c.Enabled {
		return insecure.NewCredentials(), nil
	}

	tlsCfg := &tls.Config{
		InsecureSkipVerify: c.InsecureSkipVerify,
		MinVersion:         tls.VersionTLS12,
	}

	if c.CAFile != "" {
		caCert, err := os.ReadFile(c.CAFile)
		if err != nil {
			return nil, fmt.Errorf("grpc: read CA cert: %w", err)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("grpc: failed to parse CA cert")
		}
		tlsCfg.RootCAs = caCertPool
	}

	if c.CertFile != "" && c.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("grpc: load client cert: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	return credentials.NewTLS(tlsCfg), nil
}
