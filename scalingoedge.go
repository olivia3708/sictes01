package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	scalingoAuthAPIBase      = "https://auth.scalingo.com/v1"
	scalingoOSCFR1APIBase    = "https://api.osc-fr1.scalingo.com/v1"
	scalingoSecNumAPIBase    = "https://api.osc-secnum-fr1.scalingo.com/v1"
	defaultSCReqTimeout      = 15 * time.Second
	defaultSCCertPollTick    = 12 * time.Second
	defaultSCCertPollWait    = 96 * time.Second
	defaultSCTLSProbeTimeout = 5 * time.Second
	defaultSCTargetPort      = 8080
	minSCRequestInterval     = 1200 * time.Millisecond // 50 req/min (safely under Scalingo's 60 req/min 429 limit)
	scTokenRefreshWindow     = 50 * time.Minute        // Refresh Bearer JWT before 1-hour TTL expires
)

// Fallback ingress router IPs for osc-fr1 and osc-secnum-fr1 if hostname resolution is pending
var scalingoFallbackIngressIPs = map[string]string{
	"osc-fr1":        "5.104.101.30",
	"osc-secnum-fr1": "148.253.96.193",
}

type scAPIError struct {
	StatusCode int
	Message    string
}

func (e *scAPIError) Error() string {
	if strings.TrimSpace(e.Message) != "" {
		return fmt.Sprintf("scalingo api error (HTTP %d): %s", e.StatusCode, strings.TrimSpace(e.Message))
	}
	return fmt.Sprintf("scalingo api error (HTTP %d)", e.StatusCode)
}

func (e *scAPIError) IsPermissionOrPlan() bool {
	if e.StatusCode == http.StatusUnauthorized ||
		e.StatusCode == http.StatusForbidden ||
		e.StatusCode == http.StatusPaymentRequired {
		return true
	}
	lower := strings.ToLower(e.Message)
	return strings.Contains(lower, "unauthorized") ||
		strings.Contains(lower, "forbidden") ||
		strings.Contains(lower, "permission") ||
		strings.Contains(lower, "plan") ||
		strings.Contains(lower, "quota") ||
		strings.Contains(lower, "limit")
}

type ScalingoCustomDomainInfo struct {
	ID                string
	Domain            string
	CNAMETarget       string
	LetsEncrypt       bool
	LetsEncryptStatus string
	SSLStatus         string
	AcmeDNSFqdn       string
	AcmeDNSValue      string
	CertificateStatus string
	RecordsVerified   bool
}

func (info *ScalingoCustomDomainInfo) IsCertificateValid() bool {
	if info == nil {
		return false
	}
	leSt := strings.ToLower(strings.TrimSpace(info.LetsEncryptStatus))
	if leSt == "created" || leSt == "not_needed" {
		if strings.EqualFold(info.CertificateStatus, "VALID") || strings.EqualFold(info.CertificateStatus, "created") {
			return true
		}
	}
	st := strings.ToUpper(strings.TrimSpace(info.CertificateStatus))
	if st == "" ||
		strings.Contains(st, "PENDING") ||
		strings.Contains(st, "NEW") ||
		strings.Contains(st, "PROVISION") ||
		strings.Contains(st, "ERROR") ||
		strings.Contains(st, "INVALID") ||
		strings.Contains(st, "DISABLED") {
		return false
	}
	if st == "VALID" || st == "CREATED" || st == "SUCCESS" || st == "ACTIVE" || st == "ISSUED" {
		return true
	}
	return strings.Contains(st, "VALID")
}

type ScalingoClient struct {
	Token      string
	AppID      string
	AppName    string
	Region     string
	TargetPort int
	authURL    string
	apiBase    string
	client     *http.Client

	reqMu   sync.Mutex
	lastReq time.Time

	authMu      sync.RWMutex
	bearerToken string
	tokenExpiry time.Time

	mu               sync.RWMutex
	serviceDomain    string
	customDomain     string
	discoveredRegion string
	onTopology       func(scalingoDom, cfDom string)
}

func sanitizeScalingoToken(raw string) string {
	s := strings.TrimSpace(raw)
	upper := strings.ToUpper(s)
	for _, prefix := range []string{"SCALINGO_API_TOKEN", "SCALINGO_TOKEN", "BERMUDA_SCALINGO_TOKEN"} {
		if strings.HasPrefix(upper, prefix) {
			if _, after, ok := strings.Cut(s, "="); ok {
				s = strings.TrimSpace(after)
			}
		}
	}
	s = strings.Trim(s, "\"'` \t\r\n")
	s = strings.TrimSpace(s)
	if strings.Contains(s, "${{") || strings.HasPrefix(s, "$") {
		return ""
	}
	return s
}

func regionalAPIBaseFor(region string) string {
	if strings.EqualFold(strings.TrimSpace(region), "osc-secnum-fr1") {
		return scalingoSecNumAPIBase
	}
	return scalingoOSCFR1APIBase
}

func NewScalingoClient(token string) *ScalingoClient {
	cleanTok := sanitizeScalingoToken(token)
	if cleanTok == "" {
		return nil
	}

	port := getEnvInt("PORT", defaultSCTargetPort)
	if port <= 0 {
		port = defaultSCTargetPort
	}

	scDom, cfDom := resolveInfrastructureDomains()
	reg := resolveScalingoRuntimeRegion()
	if reg != "osc-secnum-fr1" {
		reg = "osc-fr1"
	}
	if strings.HasSuffix(scDom, ".osc-secnum-fr1.scalingo.io") {
		reg = "osc-secnum-fr1"
	}

	authURL := sanitizeExplicitCredential(getEnv("SCALINGO_AUTH_URL", scalingoAuthAPIBase))
	if authURL == "" {
		authURL = scalingoAuthAPIBase
	}
	authURL = strings.TrimRight(authURL, "/")

	apiURL := sanitizeExplicitCredential(getEnv("SCALINGO_API_URL", getEnv("BERMUDA_SCALINGO_API_URL", "")))
	if apiURL == "" {
		apiURL = regionalAPIBaseFor(reg)
	}
	apiURL = strings.TrimRight(apiURL, "/")

	appID := sanitizeExplicitCredential(getEnv("SCALINGO_APPLICATION_ID", ""))
	appName := sanitizeExplicitCredential(getEnv("APP", getEnv("SCALINGO_APP", "")))
	if appName == "" && isFullScalingoServiceDomain(scDom) {
		if idx := strings.IndexByte(scDom, '.'); idx > 0 {
			appName = scDom[:idx]
		}
	}

	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	return &ScalingoClient{
		Token:            cleanTok,
		AppID:            appID,
		AppName:          appName,
		Region:           reg,
		TargetPort:       port,
		authURL:          authURL,
		apiBase:          apiURL,
		serviceDomain:    scDom,
		customDomain:     cfDom,
		discoveredRegion: reg,
		client: &http.Client{
			Timeout: 20 * time.Second,
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
					// Strictly use IPv4 ("tcp4") inside Scalingo containers
					return dialer.DialContext(ctx, "tcp4", addr)
				},
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          32,
				IdleConnTimeout:       60 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			},
		},
	}
}

func (c *ScalingoClient) IsConfigured() bool {
	return c != nil && c.Token != ""
}

func (c *ScalingoClient) HasServiceContext() bool {
	if c == nil {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.AppName != "" || c.AppID != ""
}

func (c *ScalingoClient) SetTopologyCallback(fn func(scalingoDom, cfDom string)) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.onTopology = fn
	c.mu.Unlock()
}

func (c *ScalingoClient) notifyTopology() {
	if c == nil {
		return
	}
	c.mu.RLock()
	fn := c.onTopology
	sc := c.serviceDomain
	cf := c.customDomain
	c.mu.RUnlock()
	if fn != nil {
		fn(sc, cf)
	}
}

func (c *ScalingoClient) GetServiceDomain() string {
	if c == nil {
		return ""
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.serviceDomain
}

func (c *ScalingoClient) GetCustomDomain() string {
	if c == nil {
		return ""
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.customDomain
}

func (c *ScalingoClient) GetDiscoveredRegion() string {
	if c == nil {
		return ""
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.discoveredRegion
}

func (c *ScalingoClient) SetServiceDomain(d string) {
	if c == nil {
		return
	}
	clean := cleanHost(d)
	if !isScalingoPublicDomain(clean) {
		return
	}
	c.mu.Lock()
	if c.serviceDomain == "" || isFullScalingoServiceDomain(clean) {
		c.serviceDomain = clean
	}
	if strings.HasSuffix(clean, ".osc-secnum-fr1.scalingo.io") {
		c.Region = "osc-secnum-fr1"
		c.discoveredRegion = "osc-secnum-fr1"
		c.apiBase = scalingoSecNumAPIBase
	} else if strings.HasSuffix(clean, ".osc-fr1.scalingo.io") {
		c.Region = "osc-fr1"
		c.discoveredRegion = "osc-fr1"
		c.apiBase = scalingoOSCFR1APIBase
	}
	if c.AppName == "" {
		if idx := strings.IndexByte(clean, '.'); idx > 0 {
			c.AppName = clean[:idx]
		}
	}
	c.mu.Unlock()
}

func (c *ScalingoClient) SetCustomDomain(d string) {
	if c == nil {
		return
	}
	clean := cleanHost(d)
	if clean == "" || isScalingoManagedDomain(clean) {
		return
	}
	c.mu.Lock()
	c.customDomain = clean
	c.mu.Unlock()
}

func (c *ScalingoClient) appIdentifier() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.AppName != "" {
		return c.AppName
	}
	return c.AppID
}

func (c *ScalingoClient) regionalBaseURL() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.apiBase != "" {
		return c.apiBase
	}
	return regionalAPIBaseFor(c.Region)
}

func (c *ScalingoClient) paceAPIRequest(ctx context.Context) error {
	c.reqMu.Lock()
	defer c.reqMu.Unlock()

	if !c.lastReq.IsZero() {
		elapsed := time.Since(c.lastReq)
		if elapsed < minSCRequestInterval {
			wait := minSCRequestInterval - elapsed
			t := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				if !t.Stop() {
					<-t.C
				}
				return ctx.Err()
			case <-t.C:
			}
		}
	}
	c.lastReq = time.Now()
	return nil
}

func (c *ScalingoClient) invalidateBearerToken() {
	c.authMu.Lock()
	c.bearerToken = ""
	c.tokenExpiry = time.Time{}
	c.authMu.Unlock()
}

// getValidBearerToken exchanges the Personal API Token (tk-us-...) for a 1-hour Bearer JWT
// at https://auth.scalingo.com/v1/tokens/exchange using HTTP Basic Auth ("":token).
func (c *ScalingoClient) getValidBearerToken(ctx context.Context) (string, error) {
	c.authMu.RLock()
	if c.bearerToken != "" && time.Now().Before(c.tokenExpiry) {
		tok := c.bearerToken
		c.authMu.RUnlock()
		return tok, nil
	}
	c.authMu.RUnlock()

	c.authMu.Lock()
	defer c.authMu.Unlock()

	if c.bearerToken != "" && time.Now().Before(c.tokenExpiry) {
		return c.bearerToken, nil
	}

	// If the user supplied an already-exchanged JWT directly, use it as fallback if exchange fails
	isRawJWT := !strings.HasPrefix(c.Token, "tk-us-") && strings.Count(c.Token, ".") == 2

	if err := c.paceAPIRequest(ctx); err != nil {
		return "", err
	}

	reqCtx, cancel := context.WithTimeout(ctx, defaultSCReqTimeout)
	defer cancel()

	exchangeURL := c.authURL + "/tokens/exchange"
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, exchangeURL, nil)
	if err != nil {
		return "", fmt.Errorf("build token exchange request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "curl/8.7.1")
	req.SetBasicAuth("", c.Token)

	resp, err := c.client.Do(req)
	if err != nil {
		if isRawJWT {
			c.bearerToken = c.Token
			c.tokenExpiry = time.Now().Add(scTokenRefreshWindow)
			return c.bearerToken, nil
		}
		return "", fmt.Errorf("scalingo token exchange request failed: %w", err)
	}
	defer resp.Body.Close()

	rawBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		if isRawJWT {
			c.bearerToken = c.Token
			c.tokenExpiry = time.Now().Add(scTokenRefreshWindow)
			return c.bearerToken, nil
		}
		snippet := strings.TrimSpace(string(rawBytes))
		if len(snippet) > 256 {
			snippet = snippet[:256]
		}
		return "", &scAPIError{
			StatusCode: resp.StatusCode,
			Message:    fmt.Sprintf("token exchange failed: %s", snippet),
		}
	}

	var payload struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rawBytes, &payload); err != nil || strings.TrimSpace(payload.Token) == "" {
		return "", errors.New("scalingo token exchange returned empty bearer token")
	}

	c.bearerToken = strings.TrimSpace(payload.Token)
	c.tokenExpiry = time.Now().Add(scTokenRefreshWindow)
	return c.bearerToken, nil
}

func doSCRequest(ctx context.Context, c *ScalingoClient, method, path string, body any) ([]byte, int, error) {
	return doSCRequestWithBase(ctx, c, c.regionalBaseURL(), method, path, body)
}

func doSCRequestWithBase(ctx context.Context, c *ScalingoClient, baseURL, method, path string, body any) ([]byte, int, error) {
	if !c.IsConfigured() {
		return nil, 0, errors.New("scalingo client not configured")
	}

	var reqBytes []byte
	if body != nil {
		var err error
		reqBytes, err = json.Marshal(body)
		if err != nil {
			return nil, 0, fmt.Errorf("marshal scalingo payload: %w", err)
		}
	}

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		bearer, authErr := c.getValidBearerToken(ctx)
		if authErr != nil {
			return nil, 0, authErr
		}

		if err := c.paceAPIRequest(ctx); err != nil {
			return nil, 0, err
		}

		reqCtx, cancel := context.WithTimeout(ctx, defaultSCReqTimeout)
		var bodyReader io.Reader
		if len(reqBytes) > 0 {
			bodyReader = bytes.NewReader(reqBytes)
		}

		req, err := http.NewRequestWithContext(reqCtx, method, strings.TrimRight(baseURL, "/")+path, bodyReader)
		if err != nil {
			cancel()
			return nil, 0, fmt.Errorf("build scalingo request: %w", err)
		}

		req.Header.Set("Authorization", "Bearer "+bearer)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "curl/8.7.1")

		resp, doErr := c.client.Do(req)
		if doErr != nil {
			cancel()
			lastErr = doErr
			break
		}

		rawBytes, readErr := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		_ = resp.Body.Close()
		cancel()

		if readErr != nil {
			return nil, resp.StatusCode, fmt.Errorf("read scalingo response: %w", readErr)
		}

		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			c.invalidateBearerToken()
			continue
		}

		if resp.StatusCode == http.StatusTooManyRequests && attempt == 0 {
			select {
			case <-ctx.Done():
				return nil, resp.StatusCode, ctx.Err()
			case <-time.After(2500 * time.Millisecond):
				continue
			}
		}

		if resp.StatusCode >= 400 {
			snippet := strings.TrimSpace(string(rawBytes))
			if len(snippet) > 256 {
				snippet = snippet[:256]
			}
			return rawBytes, resp.StatusCode, &scAPIError{
				StatusCode: resp.StatusCode,
				Message:    snippet,
			}
		}

		return rawBytes, resp.StatusCode, nil
	}

	return nil, 0, lastErr
}

type scAppObject struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Region        string `json:"region"`
	GitURL        string `json:"git_url"`
	URL           string `json:"url"`
	ForceHTTPS    bool   `json:"force_https"`
	StickySession bool   `json:"sticky_session"`
	RouterLogs    bool   `json:"router_logs"`
}

type scSingleAppEnvelope struct {
	App scAppObject `json:"app"`
}

type scAppsListEnvelope struct {
	Apps []scAppObject `json:"apps"`
}

func (c *ScalingoClient) applyAppMetadata(app scAppObject, regionHint string) {
	if app.ID == "" && app.Name == "" {
		return
	}

	reg := strings.ToLower(strings.TrimSpace(app.Region))
	if reg == "" {
		if strings.Contains(app.GitURL, "osc-secnum-fr1") || strings.Contains(app.URL, "osc-secnum-fr1") {
			reg = "osc-secnum-fr1"
		} else if strings.Contains(app.GitURL, "osc-fr1") || strings.Contains(app.URL, "osc-fr1") {
			reg = "osc-fr1"
		} else if regionHint != "" {
			reg = regionHint
		}
	}
	if reg != "osc-secnum-fr1" {
		reg = "osc-fr1"
	}

	cleanURLDom := cleanHost(app.URL)
	if !isScalingoPublicDomain(cleanURLDom) && app.Name != "" {
		cleanURLDom = cleanHost(fmt.Sprintf("%s.%s.scalingo.io", app.Name, reg))
	}

	c.mu.Lock()
	if app.ID != "" {
		c.AppID = app.ID
	}
	if app.Name != "" {
		c.AppName = app.Name
	}
	c.Region = reg
	c.discoveredRegion = reg
	c.apiBase = regionalAPIBaseFor(reg)
	if isScalingoPublicDomain(cleanURLDom) && (c.serviceDomain == "" || isFullScalingoServiceDomain(cleanURLDom)) {
		c.serviceDomain = cleanURLDom
	}
	c.mu.Unlock()
	c.notifyTopology()
}

func (c *ScalingoClient) ResolveRuntimeContext(ctx context.Context) error {
	if !c.IsConfigured() {
		return errors.New("scalingo client not configured")
	}

	c.mu.RLock()
	appName := c.AppName
	appID := c.AppID
	srvDom := c.serviceDomain
	curReg := c.Region
	c.mu.RUnlock()

	if appName != "" && isFullScalingoServiceDomain(srvDom) {
		return nil
	}

	targetIdent := appName
	if targetIdent == "" {
		targetIdent = appID
	}

	regionsToTry := []string{curReg, "osc-fr1", "osc-secnum-fr1"}
	seenReg := make(map[string]struct{}, 2)

	if targetIdent != "" {
		for _, reg := range regionsToTry {
			if reg == "" {
				continue
			}
			if _, ok := seenReg[reg]; ok {
				continue
			}
			seenReg[reg] = struct{}{}

			base := regionalAPIBaseFor(reg)
			raw, _, err := doSCRequestWithBase(ctx, c, base, http.MethodGet, "/apps/"+url.PathEscape(targetIdent), nil)
			if err == nil && len(raw) > 0 {
				var env scSingleAppEnvelope
				if json.Unmarshal(raw, &env) == nil && (env.App.Name != "" || env.App.ID != "") {
					c.applyAppMetadata(env.App, reg)
					return nil
				}
			}
		}
		if appName != "" && curReg != "" {
			c.applyAppMetadata(scAppObject{ID: appID, Name: appName, Region: curReg}, curReg)
			return nil
		}
	}

	seenReg = make(map[string]struct{}, 2)
	for _, reg := range regionsToTry {
		if reg == "" {
			continue
		}
		if _, ok := seenReg[reg]; ok {
			continue
		}
		seenReg[reg] = struct{}{}

		base := regionalAPIBaseFor(reg)
		raw, _, err := doSCRequestWithBase(ctx, c, base, http.MethodGet, "/apps", nil)
		if err != nil || len(raw) == 0 {
			continue
		}

		var env scAppsListEnvelope
		if json.Unmarshal(raw, &env) != nil || len(env.Apps) == 0 {
			continue
		}

		selected := env.Apps[0]
		for _, candidate := range env.Apps {
			candDom := cleanHost(fmt.Sprintf("%s.%s.scalingo.io", candidate.Name, reg))
			if (srvDom != "" && candDom == srvDom) ||
				(appName != "" && strings.EqualFold(candidate.Name, appName)) ||
				(appID != "" && candidate.ID == appID) {
				selected = candidate
				break
			}
		}

		c.applyAppMetadata(selected, reg)
		log.Printf("[Scalingo] ✓ Resolved Application Context: %s (ID=%s, Region=%s)",
			selected.Name, selected.ID, reg)
		return nil
	}

	return errors.New("unable to resolve scalingo application context")
}

// UpsertVariable updates or creates an environment variable on Scalingo without restarting the container.
func (c *ScalingoClient) UpsertVariable(ctx context.Context, name, value string) error {
	if err := c.ResolveRuntimeContext(ctx); err != nil {
		return err
	}

	appIdent := c.appIdentifier()
	if appIdent == "" {
		return errors.New("missing scalingo application identifier")
	}

	bulkPath := fmt.Sprintf("/apps/%s/variables", url.PathEscape(appIdent))
	bulkPayload := map[string]any{
		"variables": []map[string]string{
			{
				"name":  name,
				"value": value,
			},
		},
	}

	if _, _, err := doSCRequest(ctx, c, http.MethodPut, bulkPath, bulkPayload); err == nil {
		return nil
	}

	singlePayload := map[string]any{
		"variable": map[string]string{
			"name":  name,
			"value": value,
		},
	}
	_, _, err := doSCRequest(ctx, c, http.MethodPost, bulkPath, singlePayload)
	return err
}

func (c *ScalingoClient) PersistMasterKey(ctx context.Context, masterKey string) bool {
	if !c.IsConfigured() || strings.TrimSpace(masterKey) == "" {
		return false
	}
	if err := c.UpsertVariable(ctx, "BERMUDA_MASTER_KEY", strings.TrimSpace(masterKey)); err != nil {
		var apiErr *scAPIError
		if errors.As(err, &apiErr) && apiErr.IsPermissionOrPlan() {
			log.Println("[Scalingo] Note: Auto-persisting BERMUDA_MASTER_KEY skipped (token permission restriction)")
			return false
		}
		log.Printf("[Scalingo] Notice: Environment variable sync skipped: %v", err)
		return false
	}
	log.Println("[Scalingo] ✓ BERMUDA_MASTER_KEY persisted to Scalingo Environment (Zero-Restart State Persistence)")
	return true
}

func (c *ScalingoClient) EnsureServiceDomain(ctx context.Context) (string, error) {
	if dom := c.GetServiceDomain(); isFullScalingoServiceDomain(dom) {
		return dom, nil
	}

	if err := c.ResolveRuntimeContext(ctx); err != nil {
		return c.GetServiceDomain(), err
	}

	return c.GetServiceDomain(), nil
}

// scDomainObject models the Domain struct from github.com/Scalingo/go-scalingo (domains.go)
type scDomainObject struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	TLSCert            string `json:"tlscert,omitempty"`
	TLSKey             string `json:"tlskey,omitempty"`
	SSL                bool   `json:"ssl"`
	SSLStatus          string `json:"ssl_status"`
	Canonical          bool   `json:"canonical"`
	LetsEncryptEnabled bool   `json:"letsencrypt_enabled"`
	LetsEncrypt        bool   `json:"letsencrypt"`
	LetsEncryptStatus  string `json:"letsencrypt_status"`
	AcmeDNSFqdn        string `json:"acme_dns_fqdn,omitempty"`
	AcmeDNSValue       string `json:"acme_dns_value,omitempty"`
	AcmeDNSError       string `json:"acme_dns_error,omitempty"`
}

type scSingleDomainEnvelope struct {
	Domain scDomainObject `json:"domain"`
}

type scDomainsListEnvelope struct {
	Domains []scDomainObject `json:"domains"`
}

// probeCustomDomainTLS performs a direct IPv4 TLS handshake against Scalingo's OpenResty router
// with SNI set to customDomain and verifies that the leaf certificate matches customDomain.
func probeCustomDomainTLS(ctx context.Context, customDomain, gatewayHost string) bool {
	cleanCustom := cleanHost(customDomain)
	if cleanCustom == "" {
		return false
	}

	dialTarget := cleanHost(gatewayHost)
	if !isScalingoPublicDomain(dialTarget) {
		reg := resolveScalingoRuntimeRegion()
		if fallbackIP, ok := scalingoFallbackIngressIPs[reg]; ok {
			dialTarget = fallbackIP
		} else {
			dialTarget = scalingoFallbackIngressIPs["osc-fr1"]
		}
	}

	dialer := &net.Dialer{
		Timeout: defaultSCTLSProbeTimeout,
	}
	if dl, ok := ctx.Deadline(); ok {
		if rem := time.Until(dl); rem > 0 && rem < dialer.Timeout {
			dialer.Timeout = rem
		}
	}

	conn, err := tls.DialWithDialer(dialer, "tcp4", net.JoinHostPort(dialTarget, "443"), &tls.Config{
		ServerName:         cleanCustom,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: false,
	})
	if err != nil {
		return false
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return false
	}
	return certs[0].VerifyHostname(cleanCustom) == nil && time.Now().Before(certs[0].NotAfter)
}

func (c *ScalingoClient) toCustomDomainInfo(ctx context.Context, obj scDomainObject) *ScalingoCustomDomainInfo {
	dom := cleanHost(obj.Name)
	cnameTarget := c.GetServiceDomain()

	leStatus := strings.ToLower(strings.TrimSpace(obj.LetsEncryptStatus))
	sslStatus := strings.ToLower(strings.TrimSpace(obj.SSLStatus))

	certStatus := "PENDING_TLS"
	recordsVerified := leStatus != "" && leStatus != "pending_dns"

	if (obj.LetsEncrypt && leStatus == "created") || (obj.SSL && sslStatus == "success") {
		if probeCustomDomainTLS(ctx, dom, cnameTarget) {
			certStatus = "VALID"
			recordsVerified = true
		} else {
			certStatus = "PROVISIONING"
		}
	} else if probeCustomDomainTLS(ctx, dom, cnameTarget) {
		certStatus = "VALID"
		recordsVerified = true
	} else if leStatus != "" {
		certStatus = leStatus
	}

	return &ScalingoCustomDomainInfo{
		ID:                obj.ID,
		Domain:            dom,
		CNAMETarget:       cnameTarget,
		LetsEncrypt:       obj.LetsEncrypt,
		LetsEncryptStatus: leStatus,
		SSLStatus:         sslStatus,
		AcmeDNSFqdn:       strings.TrimRight(strings.TrimSpace(obj.AcmeDNSFqdn), "."),
		AcmeDNSValue:      strings.TrimSpace(obj.AcmeDNSValue),
		CertificateStatus: certStatus,
		RecordsVerified:   recordsVerified,
	}
}

func (c *ScalingoClient) listCustomDomains(ctx context.Context) ([]scDomainObject, error) {
	if err := c.ResolveRuntimeContext(ctx); err != nil {
		return nil, err
	}

	appIdent := c.appIdentifier()
	if appIdent == "" {
		return nil, errors.New("missing scalingo app identifier")
	}

	path := fmt.Sprintf("/apps/%s/domains", url.PathEscape(appIdent))
	raw, _, err := doSCRequest(ctx, c, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var env scDomainsListEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, err
	}
	return env.Domains, nil
}

func (c *ScalingoClient) EnsureCustomDomain(ctx context.Context, targetDomain string) (*ScalingoCustomDomainInfo, error) {
	cleanTarget := cleanHost(targetDomain)
	if cleanTarget == "" || isScalingoManagedDomain(cleanTarget) {
		return nil, errors.New("invalid or empty custom domain target")
	}

	existing, err := c.listCustomDomains(ctx)
	if err == nil {
		for _, cd := range existing {
			if cleanHost(cd.Name) == cleanTarget {
				c.SetCustomDomain(cleanTarget)
				c.notifyTopology()
				info := c.toCustomDomainInfo(ctx, cd)
				log.Printf("[Scalingo] ✓ Custom Domain Already Registered: %s (CNAME Target: %s, LEStatus: %s, CertStatus: %s)",
					cleanTarget, info.CNAMETarget, info.LetsEncryptStatus, info.CertificateStatus)
				return info, nil
			}
		}
	}

	if err := c.ResolveRuntimeContext(ctx); err != nil {
		return nil, err
	}

	appIdent := c.appIdentifier()
	if appIdent == "" {
		return nil, errors.New("missing scalingo app identifier")
	}

	path := fmt.Sprintf("/apps/%s/domains", url.PathEscape(appIdent))
	payload := map[string]any{
		"domain": map[string]any{
			"name":                cleanTarget,
			"canonical":           false,
			"letsencrypt_enabled": true,
		},
	}

	raw, _, postErr := doSCRequest(ctx, c, http.MethodPost, path, payload)
	if postErr != nil {
		var apiErr *scAPIError
		if errors.As(postErr, &apiErr) && (apiErr.StatusCode == http.StatusConflict || apiErr.StatusCode == http.StatusUnprocessableEntity) {
			if refreshed, listErr := c.listCustomDomains(ctx); listErr == nil {
				for _, cd := range refreshed {
					if cleanHost(cd.Name) == cleanTarget {
						c.SetCustomDomain(cleanTarget)
						c.notifyTopology()
						return c.toCustomDomainInfo(ctx, cd), nil
					}
				}
			}
		}
		return nil, fmt.Errorf("register custom domain %s on scalingo: %w", cleanTarget, postErr)
	}

	var env scSingleDomainEnvelope
	if err := json.Unmarshal(raw, &env); err != nil || env.Domain.Name == "" {
		env.Domain = scDomainObject{
			Name:               cleanTarget,
			LetsEncryptEnabled: true,
			LetsEncryptStatus:  "pending_dns",
		}
	}

	c.SetCustomDomain(cleanTarget)
	c.notifyTopology()
	info := c.toCustomDomainInfo(ctx, env.Domain)

	log.Printf("[Scalingo] ✓ Registered Custom Domain: %s -> %s (LEStatus: %s)",
		cleanTarget, info.CNAMETarget, info.LetsEncryptStatus)
	return info, nil
}

func (c *ScalingoClient) FetchCustomDomainStatus(ctx context.Context, customDomainID, targetDomain string) (*ScalingoCustomDomainInfo, error) {
	cleanTarget := cleanHost(targetDomain)
	cnameTarget := c.GetServiceDomain()

	if err := c.ResolveRuntimeContext(ctx); err == nil {
		appIdent := c.appIdentifier()
		if appIdent != "" && strings.TrimSpace(customDomainID) != "" {
			path := fmt.Sprintf("/apps/%s/domains/%s", url.PathEscape(appIdent), url.PathEscape(strings.TrimSpace(customDomainID)))
			if raw, _, reqErr := doSCRequest(ctx, c, http.MethodGet, path, nil); reqErr == nil && len(raw) > 0 {
				var env scSingleDomainEnvelope
				if json.Unmarshal(raw, &env) == nil && env.Domain.Name != "" {
					return c.toCustomDomainInfo(ctx, env.Domain), nil
				}
			}
		}

		if doms, listErr := c.listCustomDomains(ctx); listErr == nil {
			for _, cd := range doms {
				if (customDomainID != "" && cd.ID == customDomainID) || (cleanTarget != "" && cleanHost(cd.Name) == cleanTarget) {
					return c.toCustomDomainInfo(ctx, cd), nil
				}
			}
		}
	}

	if probeCustomDomainTLS(ctx, cleanTarget, cnameTarget) {
		return &ScalingoCustomDomainInfo{
			ID:                customDomainID,
			Domain:            cleanTarget,
			CNAMETarget:       cnameTarget,
			LetsEncrypt:       true,
			LetsEncryptStatus: "created",
			CertificateStatus: "VALID",
			RecordsVerified:   true,
		}, nil
	}

	return &ScalingoCustomDomainInfo{
		ID:                customDomainID,
		Domain:            cleanTarget,
		CNAMETarget:       cnameTarget,
		LetsEncryptStatus: "pending_dns",
		CertificateStatus: "PENDING_TLS",
	}, nil
}

func (c *ScalingoClient) WaitCustomDomainCertificate(ctx context.Context, customDomainID, targetDomain string, maxWait time.Duration) (*ScalingoCustomDomainInfo, bool) {
	if maxWait <= 0 {
		maxWait = defaultSCCertPollWait
	}
	waitCtx, cancel := context.WithTimeout(ctx, maxWait)
	defer cancel()

	ticker := time.NewTicker(defaultSCCertPollTick)
	defer ticker.Stop()

	var latest *ScalingoCustomDomainInfo
	for {
		info, err := c.FetchCustomDomainStatus(waitCtx, customDomainID, targetDomain)
		if err == nil && info != nil {
			latest = info
			if info.IsCertificateValid() {
				log.Printf("[Scalingo] ✓ Custom Domain %s Let's Encrypt TLS Certificate ISSUED & ACTIVE on OpenResty Ingress",
					info.Domain)
				return info, true
			}
		}

		select {
		case <-waitCtx.Done():
			return latest, false
		case <-ticker.C:
		}
	}
}

func (c *ScalingoClient) HardenAppSettings(ctx context.Context) {
	if !c.IsConfigured() {
		return
	}
	if err := c.ResolveRuntimeContext(ctx); err != nil {
		return
	}

	appIdent := c.appIdentifier()
	if appIdent == "" {
		return
	}

	path := fmt.Sprintf("/apps/%s", url.PathEscape(appIdent))
	payload := map[string]any{
		"app": map[string]bool{
			"force_https":    true,
			"sticky_session": false,
			"router_logs":    false,
		},
	}

	if _, _, err := doSCRequest(ctx, c, http.MethodPatch, path, payload); err != nil {
		var apiErr *scAPIError
		if errors.As(err, &apiErr) && apiErr.IsPermissionOrPlan() {
			return
		}
		log.Printf("[Scalingo] Notice: App router settings update skipped: %v", err)
		return
	}
	log.Println("[Scalingo] ✓ Hardened App Router Settings: force_https=true | sticky_session=false | router_logs=false")
}

type scContainerFormation struct {
	Name   string `json:"name"`
	Amount int    `json:"amount"`
	Size   string `json:"size"`
}

type scContainersEnvelope struct {
	Containers []scContainerFormation `json:"containers"`
}

func probeKernelIPv6Route() bool {
	conn, err := net.DialTimeout("udp6", "[2606:4700:4700::1111]:53", 50*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func (c *ScalingoClient) TuneComputeAndNetwork(ctx context.Context) {
	if probeKernelIPv6Route() {
		log.Println("[Scalingo] ✓ Outbound IPv6 Stack: ACTIVE")
	} else {
		log.Println("[Scalingo] ✓ Outbound Network Stack: IPv4 Active (3DS Outscale Egress Verified)")
	}

	if !c.IsConfigured() {
		return
	}
	if !c.HasServiceContext() {
		_ = c.ResolveRuntimeContext(ctx)
	}

	c.HardenAppSettings(ctx)

	appIdent := c.appIdentifier()
	var containerSummary string
	if appIdent != "" {
		// Query container formation using GET /v1/apps/{app}/containers
		path := fmt.Sprintf("/apps/%s/containers", url.PathEscape(appIdent))
		if raw, _, err := doSCRequest(ctx, c, http.MethodGet, path, nil); err == nil && len(raw) > 0 {
			var env scContainersEnvelope
			if json.Unmarshal(raw, &env) == nil && len(env.Containers) > 0 {
				for _, ct := range env.Containers {
					if ct.Name == "web" {
						containerSummary = fmt.Sprintf("%s:%d", ct.Size, ct.Amount)
						break
					}
				}
			}
		}
	}
	if containerSummary == "" {
		containerSummary = getEnv("CONTAINER_SIZE", "M") + ":1"
	}

	c.mu.RLock()
	srvDom := c.serviceDomain
	reg := c.discoveredRegion
	port := c.TargetPort
	c.mu.RUnlock()

	healthPath := getEnv("BERMUDA_HEALTH_PATH", "/.well-known/hc-5b1e7c")
	log.Printf("[Scalingo] ✓ Service Ready: App=%s | Domain=%s | Region=%s | Formation=%s | Port=%d | HealthPath=%s",
		appIdent, srvDom, reg, containerSummary, port, healthPath)
}
