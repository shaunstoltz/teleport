package integration

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/auth/keystore"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/backend/lite"
	"github.com/gravitational/teleport/lib/service"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/teleport/lib/utils/testlog"
	"github.com/jonboulle/clockwork"

	"github.com/gravitational/trace"

	"github.com/stretchr/testify/require"
)

type teleportService struct {
	config         *service.Config
	process        *service.TeleportProcess
	serviceChannel chan *service.TeleportProcess
	errorChannel   chan error
}

func newTeleportService(config *service.Config) *teleportService {
	return &teleportService{
		config:         config,
		serviceChannel: make(chan *service.TeleportProcess, 10),
		errorChannel:   make(chan error, 10),
	}
}

func (t *teleportService) start(ctx context.Context) {
	go func() {
		t.errorChannel <- service.Run(ctx, *t.config, func(cfg *service.Config) (service.Process, error) {
			svc, err := service.NewTeleport(cfg)
			if err == nil {
				t.serviceChannel <- svc
			}
			return svc, err
		})
	}()
}

func (t *teleportService) waitForStart(ctx context.Context) error {
	t.start(ctx)
	select {
	case t.process = <-t.serviceChannel:
	case err := <-t.errorChannel:
		return trace.Wrap(err)
	case <-ctx.Done():
		return trace.Wrap(ctx.Err())
	}
	return nil
}

func (t *teleportService) waitForReady(ctx context.Context) error {
	eventChannel := make(chan service.Event, 1)
	t.process.WaitForEvent(ctx, service.TeleportReadyEvent, eventChannel)
	select {
	case <-eventChannel:
	case <-ctx.Done():
		return trace.Wrap(ctx.Err())
	}
	return nil
}

func (t *teleportService) waitForRestart(ctx context.Context) error {
	// get the new process
	var newProcess *service.TeleportProcess
	select {
	case newProcess = <-t.serviceChannel:
	case err := <-t.errorChannel:
		return trace.Wrap(err)
	case <-ctx.Done():
		return trace.Wrap(ctx.Err())
	}

	// wait for the old process to die
	done := make(chan struct{})
	go func() {
		t.process.Supervisor.Wait()
		done <- struct{}{}
	}()
	select {
	case <-done:
	case <-ctx.Done():
		return trace.Wrap(ctx.Err())
	}
	t.process = newProcess

	// wait for the new process to be ready
	return trace.Wrap(t.waitForReady(ctx))
}

func (t *teleportService) waitForLocalAdditionalKeys(ctx context.Context) error {
	clusterName, err := t.process.GetAuthServer().GetClusterName()
	if err != nil {
		return trace.Wrap(err)
	}
	allHaveLocalAdditionalKeys := false
	for !allHaveLocalAdditionalKeys {
		select {
		case <-ctx.Done():
			return trace.Wrap(ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
		userCAID := types.CertAuthID{DomainName: clusterName.GetClusterName(), Type: types.UserCA}
		hostCAID := types.CertAuthID{DomainName: clusterName.GetClusterName(), Type: types.HostCA}
		jwtCAID := types.CertAuthID{DomainName: clusterName.GetClusterName(), Type: types.JWTSigner}
		allHaveLocalAdditionalKeys = true
		for _, caID := range []types.CertAuthID{userCAID, hostCAID, jwtCAID} {
			ca, err := t.process.GetAuthServer().GetCertAuthority(caID, true)
			if err != nil {
				return trace.Wrap(err)
			}
			allHaveLocalAdditionalKeys = allHaveLocalAdditionalKeys && t.process.GetAuthServer().GetKeyStore().HasLocalAdditionalKeys(ca)
		}
	}
	return nil
}

type TeleportServices []*teleportService

func (s TeleportServices) forEach(f func(t *teleportService) error) error {
	for i := range s {
		if err := f(s[i]); err != nil {
			return trace.Wrap(err)
		}
	}
	return nil
}

func (s TeleportServices) waitForStart(ctx context.Context) error {
	return s.forEach(func(t *teleportService) error { return t.waitForStart(ctx) })
}

func (s TeleportServices) waitForRestart(ctx context.Context) error {
	return s.forEach(func(t *teleportService) error { return t.waitForRestart(ctx) })
}

func (s TeleportServices) waitForLocalAdditionalKeys(ctx context.Context) error {
	return s.forEach(func(t *teleportService) error { return t.waitForLocalAdditionalKeys(ctx) })
}

func TestHSMRotation(t *testing.T) {
	log := testlog.FailureOnly(t)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	numAuthServers := 2

	baseDataDir := t.TempDir()
	sharedBackendDir := t.TempDir()

	var teleportServices TeleportServices

	hostName, err := os.Hostname()
	require.NoError(t, err)
	for i := 0; i < numAuthServers; i++ {
		siteName := fmt.Sprintf("testhost-%d", i)
		dataDir, err := os.MkdirTemp(baseDataDir, siteName)

		config := service.MakeDefaultConfig()
		config.Log = log
		config.SSH.Enabled = false
		config.Proxy.Enabled = false
		config.PollingPeriod = 500 * time.Millisecond
		config.ClientTimeout = time.Second
		config.ShutdownTimeout = 2 * config.ClientTimeout
		config.DataDir = dataDir
		config.Auth.SSHAddr.Addr = net.JoinHostPort(hostName, ports.Pop())
		config.CachePolicy.Enabled = true
		config.Auth.PublicAddrs = []utils.NetAddr{
			{
				AddrNetwork: "tcp",
				Addr:        hostName,
			},
		}
		config.Auth.ClusterName, err = services.NewClusterNameWithRandomID(types.ClusterNameSpecV2{
			ClusterName: "testcluster",
		})
		require.NoError(t, err)
		config.AuthServers = append(config.AuthServers, config.Auth.SSHAddr)
		config.Auth.StorageConfig = backend.Config{
			Type:   lite.GetName(),
			Params: backend.Params{"path": sharedBackendDir, "poll_stream_period": 50 * time.Millisecond},
		}
		fakeClock := clockwork.NewFakeClock()
		config.Clock = fakeClock
		go func() {
			for {
				select {
				case <-time.After(10 * time.Millisecond):
					fakeClock.Advance(100 * time.Millisecond)
				case <-ctx.Done():
					return
				}
			}
		}()
		config.KeyStore = keystore.Config{
			Path:       os.Getenv("SOFTHSM2_PATH"),
			TokenLabel: "test",
			Pin:        "password",
		}
		teleportServices = append(teleportServices, newTeleportService(config))
	}
	require.NoError(t, teleportServices.waitForStart(ctx))

	err = teleportServices[0].process.GetAuthServer().RotateCertAuthority(auth.RotateRequest{
		//Type:        types.HostCA,
		TargetPhase: types.RotationPhaseInit,
		Mode:        types.RotationModeManual,
	})
	require.NoError(t, err)
	require.NoError(t, teleportServices.waitForLocalAdditionalKeys(ctx))

	err = teleportServices[0].process.GetAuthServer().RotateCertAuthority(auth.RotateRequest{
		TargetPhase: types.RotationPhaseUpdateClients,
		Mode:        types.RotationModeManual,
	})
	require.NoError(t, err)
	require.NoError(t, teleportServices.waitForRestart(ctx))

	err = teleportServices[0].process.GetAuthServer().RotateCertAuthority(auth.RotateRequest{
		TargetPhase: types.RotationPhaseUpdateServers,
		Mode:        types.RotationModeManual,
	})
	require.NoError(t, err)
	require.NoError(t, teleportServices.waitForRestart(ctx))

	err = teleportServices[0].process.GetAuthServer().RotateCertAuthority(auth.RotateRequest{
		TargetPhase: types.RotationPhaseStandby,
		Mode:        types.RotationModeManual,
	})
	require.NoError(t, err)
	require.NoError(t, teleportServices.waitForRestart(ctx))

	for i := range teleportServices {
		require.NoError(t, teleportServices[i].process.GetAuthServer().Close())
	}
}
