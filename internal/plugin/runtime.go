package plugin

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"

	"github.com/giraphant/cpa-plugin-usage-quota-guard/internal/abi"
	keyauth "github.com/giraphant/cpa-plugin-usage-quota-guard/internal/auth"
	"github.com/giraphant/cpa-plugin-usage-quota-guard/internal/config"
	"github.com/giraphant/cpa-plugin-usage-quota-guard/internal/management"
	"github.com/giraphant/cpa-plugin-usage-quota-guard/internal/routehealth"
	"github.com/giraphant/cpa-plugin-usage-quota-guard/internal/store"
	usageconv "github.com/giraphant/cpa-plugin-usage-quota-guard/internal/usage"
)

const (
	Version    = "0.1.0"
	Identifier = "usage-quota-guard"
)

var global = &Runtime{}

type Runtime struct {
	mu    sync.RWMutex
	cfg   config.Config
	store *store.Store
}

func HandleMethod(method string, request []byte) ([]byte, error) {
	return global.HandleMethod(method, request)
}

func Shutdown() {
	global.Shutdown()
}

func (r *Runtime) HandleMethod(method string, request []byte) ([]byte, error) {
	switch method {
	case pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure:
		if err := r.configure(request); err != nil {
			return nil, err
		}
		return abi.OKEnvelope(abi.PluginRegistration(Version))
	case pluginabi.MethodPluginShutdown:
		r.Shutdown()
		return abi.OKEnvelope(map[string]any{})
	case pluginabi.MethodFrontendAuthIdentifier:
		return abi.OKEnvelope(abi.IdentifierResponse{Identifier: Identifier})
	case pluginabi.MethodFrontendAuthAuthenticate:
		return r.frontendAuth(request)
	case pluginabi.MethodUsageHandle:
		return r.handleUsage(request)
	case pluginabi.MethodSchedulerPick:
		return r.pick(request)
	case pluginabi.MethodManagementRegister:
		return abi.OKEnvelope(management.Register())
	case pluginabi.MethodManagementHandle:
		return r.handleManagement(request)
	default:
		return abi.ErrorEnvelope("unknown_method", "unknown method: "+method), nil
	}
}

func (r *Runtime) configure(request []byte) error {
	var req abi.LifecycleRequest
	if len(request) > 0 {
		if err := json.Unmarshal(request, &req); err != nil {
			return err
		}
	}
	cfg, err := config.Load(req.ConfigYAML)
	if err != nil {
		return err
	}
	st, err := store.Open(cfg)
	if err != nil {
		return err
	}
	r.mu.Lock()
	old := r.store
	r.cfg = cfg
	r.store = st
	r.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	return nil
}

func (r *Runtime) Shutdown() {
	r.mu.Lock()
	st := r.store
	r.store = nil
	r.mu.Unlock()
	if st != nil {
		_ = st.Close()
	}
}

func (r *Runtime) snapshot() (config.Config, *store.Store) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cfg, r.store
}

func (r *Runtime) frontendAuth(request []byte) ([]byte, error) {
	cfg, st := r.snapshot()
	if st == nil {
		return abi.OKEnvelope(pluginapi.FrontendAuthResponse{Authenticated: false, Metadata: map[string]string{"reason": "store_unavailable"}})
	}
	var req pluginapi.FrontendAuthRequest
	if err := json.Unmarshal(request, &req); err != nil {
		return nil, err
	}
	rawKey, source, ok := keyauth.ExtractAPIKey(req.Headers, req.Query, cfg.FrontendAuth.AcceptedSources)
	if !ok {
		return abi.OKEnvelope(pluginapi.FrontendAuthResponse{Authenticated: false, Metadata: map[string]string{"reason": "missing_key"}})
	}
	res, err := st.AuthenticateKey(rawKey, time.Now())
	if err != nil {
		return nil, err
	}
	if !res.Allowed {
		return abi.OKEnvelope(pluginapi.FrontendAuthResponse{Authenticated: false, Metadata: map[string]string{"reason": res.Reason, "fingerprint": res.Fingerprint}})
	}
	return abi.OKEnvelope(pluginapi.FrontendAuthResponse{
		Authenticated: true,
		Principal:     res.KeyHash,
		Metadata: map[string]string{
			"source":       source,
			"fingerprint":  res.Fingerprint,
			"display_name": res.DisplayName,
			"quota_status": "ok",
		},
	})
}

func (r *Runtime) handleUsage(request []byte) ([]byte, error) {
	cfg, st := r.snapshot()
	if st == nil {
		return abi.OKEnvelope(map[string]any{"ignored": "store_unavailable"})
	}
	var record pluginapi.UsageRecord
	if err := json.Unmarshal(request, &record); err != nil {
		return nil, err
	}
	if strings.TrimSpace(record.APIKey) != "" {
		if err := st.RecordUsage(usageconv.FromCPA(record, cfg)); err != nil {
			return nil, err
		}
	}
	if ban, ok := routehealth.ObservationFromUsage(record, cfg, time.Now()); ok {
		if err := st.AddOrExtendBan(ban); err != nil {
			return nil, err
		}
	}
	_ = st.PruneUsageEvents(cfg.RetentionCutoff(time.Now()))
	return abi.OKEnvelope(map[string]any{})
}

func (r *Runtime) pick(request []byte) ([]byte, error) {
	_, st := r.snapshot()
	if st == nil {
		return abi.OKEnvelope(pluginapi.SchedulerPickResponse{Handled: false})
	}
	var req pluginapi.SchedulerPickRequest
	if err := json.Unmarshal(request, &req); err != nil {
		return nil, err
	}
	if len(req.Candidates) == 0 {
		return abi.OKEnvelope(pluginapi.SchedulerPickResponse{Handled: false})
	}
	candidates := append([]pluginapi.SchedulerAuthCandidate(nil), req.Candidates...)
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].Priority != candidates[j].Priority {
			return candidates[i].Priority > candidates[j].Priority
		}
		return candidates[i].ID < candidates[j].ID
	})
	now := time.Now()
	for _, candidate := range candidates {
		if !candidateStatusUsable(candidate.Status) {
			continue
		}
		targetKey := routehealth.CandidateTargetKey(candidate, req.Model)
		if _, active, err := st.ActiveBan(targetKey, now); err == nil && active {
			continue
		} else if err != nil {
			return nil, err
		}
		return abi.OKEnvelope(pluginapi.SchedulerPickResponse{AuthID: candidate.ID, Handled: true})
	}
	return abi.OKEnvelope(pluginapi.SchedulerPickResponse{Handled: false})
}

func candidateStatusUsable(status string) bool {
	status = strings.ToLower(strings.TrimSpace(status))
	return status == "" || status == "active" || status == "ok" || status == "available" || status == "ready"
}

func (r *Runtime) handleManagement(request []byte) ([]byte, error) {
	cfg, st := r.snapshot()
	var req pluginapi.ManagementRequest
	if err := json.Unmarshal(request, &req); err != nil {
		return nil, err
	}
	resp := management.Handle(req, st, cfg)
	if resp.StatusCode == 0 {
		resp.StatusCode = http.StatusOK
	}
	return abi.OKEnvelope(resp)
}

func ResetForTests() {
	global.Shutdown()
	global = &Runtime{}
}

func StoreForTests() (*store.Store, error) {
	_, st := global.snapshot()
	if st == nil {
		return nil, errors.New("store unavailable")
	}
	return st, nil
}
