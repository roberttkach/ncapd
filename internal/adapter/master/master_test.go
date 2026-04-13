package master

import (
	"context"
	"net"
	"testing"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/roberttkach/ncapd/internal/core"
	ncapdpb "github.com/roberttkach/ncapd/proto"
)

var _ ncapdpb.ProbeServiceServer = (*mockProbeServer)(nil)

type mockProbeServer struct {
	ncapdpb.UnimplementedProbeServiceServer
	submitCalls int
	lastReq     *ncapdpb.SubmitRequest
	shouldFail  bool
}

func (m *mockProbeServer) Submit(_ context.Context, req *ncapdpb.SubmitRequest) (*ncapdpb.SubmitResponse, error) {
	m.submitCalls++
	m.lastReq = req
	if m.shouldFail {
		return &ncapdpb.SubmitResponse{Success: false, Error: "server error"}, nil
	}
	return &ncapdpb.SubmitResponse{Success: true}, nil
}

func setupTestClient(t *testing.T, shouldFail bool) (*Client, *mockProbeServer) {
	t.Helper()

	log := zap.NewNop()
	mock := &mockProbeServer{shouldFail: shouldFail}

	lis := bufconn.Listen(1024 * 1024)
	s := grpc.NewServer()
	ncapdpb.RegisterProbeServiceServer(s, mock)
	go func() {
		if err := s.Serve(lis); err != nil {
			t.Logf("server exited: %v", err)
		}
	}()
	t.Cleanup(func() { s.Stop() })

	dialer := func(context.Context, string) (net.Conn, error) {
		return lis.Dial()
	}

	conn, err := grpc.DialContext(context.Background(), "bufnet",
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc dial: %v", err)
	}

	return &Client{
		conn:   conn,
		client: ncapdpb.NewProbeServiceClient(conn),
		nodeID: "test-node",
		log:    log,
	}, mock
}

func TestClient_Submit(t *testing.T) {
	t.Run("successful submit", func(t *testing.T) {
		client, mock := setupTestClient(t, false)

		result := core.Result{
			ID:     "check-1",
			Type:   core.TypePortBlock,
			Status: core.OK,
			At:     time.Now(),
			Host:   "example.com",
		}

		err := client.Submit(context.Background(), result)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if mock.submitCalls != 1 {
			t.Errorf("submit calls = %d, want 1", mock.submitCalls)
		}
		if mock.lastReq == nil {
			t.Fatal("expected request to be received")
		}
		if len(mock.lastReq.Results) != 1 {
			t.Errorf("results = %d, want 1", len(mock.lastReq.Results))
		}
		if mock.lastReq.NodeId != "test-node" {
			t.Errorf("node ID = %q, want 'test-node'", mock.lastReq.NodeId)
		}
	})

	t.Run("submit failure logged", func(t *testing.T) {
		client, _ := setupTestClient(t, true)

		result := core.Result{
			ID:     "check-2",
			Type:   core.TypePortBlock,
			Status: core.Blocked,
			At:     time.Now(),
		}

		err := client.Submit(context.Background(), result)
		if err == nil {
			t.Error("expected error from failed submit")
		}
	})
}

func TestClient_SubmitBatch(t *testing.T) {
	t.Run("successful batch submit", func(t *testing.T) {
		client, mock := setupTestClient(t, false)

		results := []core.Result{
			{ID: "r1", Type: core.TypePortBlock, Status: core.OK, At: time.Now()},
			{ID: "r2", Type: core.TypeDNSFilter, Status: core.Blocked, At: time.Now()},
			{ID: "r3", Type: core.TypeSNIInspect, Status: core.Error, At: time.Now()},
		}

		err := client.SubmitBatch(context.Background(), results)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if mock.submitCalls != 1 {
			t.Errorf("submit calls = %d, want 1", mock.submitCalls)
		}
		if len(mock.lastReq.Results) != 3 {
			t.Errorf("results in batch = %d, want 3", len(mock.lastReq.Results))
		}
	})

	t.Run("empty nodeID → no submit", func(t *testing.T) {
		client, mock := setupTestClient(t, false)
		client.nodeID = ""

		results := []core.Result{
			{ID: "r1", Type: core.TypePortBlock, Status: core.OK},
		}

		err := client.SubmitBatch(context.Background(), results)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if mock.submitCalls != 0 {
			t.Errorf("submit calls for empty nodeID = %d, want 0", mock.submitCalls)
		}
	})

	t.Run("empty results → no submit", func(t *testing.T) {
		client, mock := setupTestClient(t, false)

		err := client.SubmitBatch(context.Background(), []core.Result{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if mock.submitCalls != 0 {
			t.Errorf("submit calls for empty results = %d, want 0", mock.submitCalls)
		}
	})
}

func TestClient_Close(t *testing.T) {
	t.Run("close connected client", func(t *testing.T) {
		client, _ := setupTestClient(t, false)

		err := client.Close()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("close nil conn", func(t *testing.T) {
		client := &Client{}
		err := client.Close()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestTLSConfig_BuildCredentials(t *testing.T) {
	tests := []struct {
		name    string
		tlsCfg  TLSConfig
		wantErr bool
	}{
		{
			name:    "disabled TLS",
			tlsCfg:  TLSConfig{Enabled: false},
			wantErr: false,
		},
		{
			name: "enabled without certs",
			tlsCfg: TLSConfig{
				Enabled:            true,
				InsecureSkipVerify: true,
			},
			wantErr: false,
		},
		{
			name: "invalid CA file",
			tlsCfg: TLSConfig{
				Enabled: true,
				CAFile:  "/nonexistent/ca.pem",
			},
			wantErr: true,
		},
		{
			name: "invalid client cert",
			tlsCfg: TLSConfig{
				Enabled:  true,
				CertFile: "/nonexistent/cert.pem",
				KeyFile:  "/nonexistent/key.pem",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			creds, err := tt.tlsCfg.buildCredentials()
			if (err != nil) != tt.wantErr {
				t.Errorf("buildCredentials() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && creds == nil {
				t.Error("expected non-nil credentials")
			}
		})
	}
}
