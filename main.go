package main

import (
	"context"
	"errors"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	defaultPort               = "8080"
	fallbackSelfMemMB         = 96
	fallbackWorkerMemMB       = 320
	defaultGOMAXPROCS         = 2
	gatewayMemPercent         = 14
	workerMemPercent          = 56
	httpDrainTimeout          = 8 * time.Second
	edgeKeepAlivePeriod       = 15 * time.Second
	serverIdleTimeout         = 55 * time.Second // Aligned under Scalingo OpenResty's 60s timeout window
	drainPropagationWindow    = 450 * time.Millisecond
	startupOrchestrationDelay = 6 * time.Second
	dnsPropagationSettleDelay = 4 * time.Second
	tcpUserTimeoutOpt         = 18
)

func containerMemoryLimit() (uint64, bool) {
	// Priority 1: Scalingo's native CONTAINER_MEMORY environment variable (in bytes)
	if rawMem := strings.TrimSpace(os.Getenv("CONTAINER_MEMORY")); rawMem != "" {
		if n, err := strconv.ParseUint(rawMem, 10, 64); err == nil && n > 0 && n < 1<<50 {
			return n, true
		}
	}

	// Priority 2: Linux Cgroup v2 / v1 memory ceiling files
	candidates := []string{
		"/sys/fs/cgroup/memory.max",
		"/sys/fs/cgroup/memory/memory.limit_in_bytes",
	}
	for _, p := range candidates {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		s := strings.TrimSpace(string(data))
		if s == "" || s == "max" {
			continue
		}
		n, err := strconv.ParseUint(s, 10, 64)
		if err != nil || n == 0 || n >= 1<<50 {
			continue
		}
		return n, true
	}
	return 0, false
}

func deriveMemoryBudget() (gwMB, workerMB int) {
	gwMB, workerMB = fallbackSelfMemMB, fallbackWorkerMemMB
	limit, limited := containerMemoryLimit()
	if limited {
		totalMB := int(limit >> 20)
		gwMB = totalMB * gatewayMemPercent / 100
		workerMB = totalMB * workerMemPercent / 100

		// Keep total soft limit at <= 70% of CONTAINER_MEMORY to prevent OOM Kill on no-swap Scalingo containers
		allowedMB := totalMB * 70 / 100
		if gwMB < 32 {
			gwMB = 32
		}
		if workerMB < 64 {
			workerMB = 64
		}
		if total := gwMB + workerMB; total > allowedMB && allowedMB >= 96 {
			gwMB = allowedMB * gatewayMemPercent / 70
			workerMB = allowedMB * workerMemPercent / 70
		}
	}

	gwMB = getEnvInt("BERMUDA_SELF_MEM_MB", gwMB)
	workerMB = getEnvInt("BERMUDA_WORKER_MEM_MB", workerMB)
	return gwMB, workerMB
}

func applyMemoryCeiling(selfMB int) {
	debug.SetMemoryLimit(int64(selfMB) << 20)
	debug.SetGCPercent(100)
}

func cgroupCPUQuota() (float64, bool) {
	if data, err := os.ReadFile("/sys/fs/cgroup/cpu.max"); err == nil {
		f := strings.Fields(string(data))
		if len(f) == 2 && f[0] != "max" {
			q, e1 := strconv.ParseFloat(f[0], 64)
			p, e2 := strconv.ParseFloat(f[1], 64)
			if e1 == nil && e2 == nil && q > 0 && p > 0 {
				return q / p, true
			}
		}
	}
	qb, e1 := os.ReadFile("/sys/fs/cgroup/cpu/cpu.cfs_quota_us")
	pb, e2 := os.ReadFile("/sys/fs/cgroup/cpu/cpu.cfs_period_us")
	if e1 == nil && e2 == nil {
		q, e3 := strconv.ParseFloat(strings.TrimSpace(string(qb)), 64)
		p, e4 := strconv.ParseFloat(strings.TrimSpace(string(pb)), 64)
		if e3 == nil && e4 == nil && q > 0 && p > 0 {
			return q / p, true
		}
	}
	return 0, false
}

func applyGOMAXPROCS() int {
	n := getEnvInt("BERMUDA_GOMAXPROCS", 0)
	if n == 0 {
		if q, ok := cgroupCPUQuota(); ok {
			n = int(math.Ceil(q))
		}
	}
	if n < 2 {
		n = defaultGOMAXPROCS
	}
	if cpus := runtime.NumCPU(); n > cpus && cpus > 0 {
		n = cpus
	}
	runtime.GOMAXPROCS(n)
	return n
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func sleepContext(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func cleanHost(h string) string {
	h = strings.TrimSpace(h)
	if strings.HasPrefix(h, "${{") || strings.HasPrefix(h, "$") || strings.Contains(h, "%APP%") {
		return ""
	}
	h = strings.TrimPrefix(h, "https://")
	h = strings.TrimPrefix(h, "http://")
	if slashIdx := strings.IndexByte(h, '/'); slashIdx != -1 {
		h = h[:slashIdx]
	}
	h = strings.TrimRight(h, "/.")
	if idx := strings.Index(h, ":"); idx != -1 && !strings.Contains(h, "]") {
		h = h[:idx]
	}
	return strings.ToLower(strings.TrimSpace(h))
}

func isScalingoManagedDomain(h string) bool {
	if h == "" {
		return false
	}
	return strings.Contains(h, "scalingo.io") ||
		strings.Contains(h, "scalingo.com") ||
		strings.HasSuffix(h, ".internal") ||
		strings.HasSuffix(h, ".local")
}

func isScalingoPublicDomain(h string) bool {
	return h != "" &&
		strings.Contains(h, "scalingo.io") &&
		!strings.HasSuffix(h, ".internal") &&
		!strings.HasSuffix(h, ".local")
}

func normalizeRegion(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	switch {
	case strings.Contains(s, "secnum"):
		return "osc-secnum-fr1"
	case strings.Contains(s, "osc-fr1") || strings.Contains(s, "paris") || strings.Contains(s, "france") || strings.Contains(s, "outscale") || strings.Contains(s, "fr1"):
		return "osc-fr1"
	case strings.Contains(s, "frankfurt") || strings.Contains(s, "fra") || strings.Contains(s, "eu-central") || strings.Contains(s, "germany"):
		return "eu-central"
	case strings.Contains(s, "europe-west4") || strings.Contains(s, "amsterdam") || strings.Contains(s, "nl"):
		return "europe-west4"
	case strings.Contains(s, "virginia") || strings.Contains(s, "iad") || strings.Contains(s, "us-east"):
		return "us-east4"
	case strings.Contains(s, "oregon") || strings.Contains(s, "california") || strings.Contains(s, "us-west"):
		return "us-west"
	case strings.Contains(s, "singapore") || strings.Contains(s, "sin") || strings.Contains(s, "asia"):
		return "asia-southeast1"
	default:
		return "osc-fr1"
	}
}

func resolveScalingoRuntimeRegion() string {
	for _, key := range []string{"BERMUDA_REGION", "REGION_NAME", "SCALINGO_REGION", "REGION"} {
		if val := strings.TrimSpace(getEnv(key, "")); val != "" {
			return normalizeRegion(val)
		}
	}
	return "osc-fr1"
}

func resolveInfrastructureDomains() (scalingoDomain, customDomain string) {
	appName := strings.ToLower(strings.TrimSpace(getEnv("APP", getEnv("SCALINGO_APP", ""))))
	reg := resolveScalingoRuntimeRegion()
	if reg != "osc-secnum-fr1" {
		reg = "osc-fr1"
	}

	var synthesizedAppDomain string
	if appName != "" && !strings.Contains(appName, ".") && !strings.Contains(appName, "%") {
		synthesizedAppDomain = appName + "." + reg + ".scalingo.io"
	}

	originURL := cleanHost(getEnv("PUBLIC_ORIGIN_URL", ""))
	publicDomain := cleanHost(getEnv("SCALINGO_PUBLIC_DOMAIN", getEnv("SCALINGO_DOMAIN", "")))
	explicitScalingo := cleanHost(getEnv("SCALINGO_DEFAULT_DOMAIN", getEnv("BERMUDA_SCALINGO_DOMAIN", "")))
	customEnv := cleanHost(getEnv("CUSTOM_DOMAIN", getEnv("BERMUDA_CUSTOM_DOMAIN", "")))

	for _, candidate := range []string{explicitScalingo, publicDomain, originURL, synthesizedAppDomain} {
		if isScalingoPublicDomain(candidate) {
			scalingoDomain = candidate
			break
		}
	}

	for _, candidate := range []string{customEnv, publicDomain, originURL, explicitScalingo} {
		if candidate != "" && !isScalingoManagedDomain(candidate) {
			customDomain = candidate
			break
		}
	}

	return scalingoDomain, customDomain
}

func orchestrateCloudInfrastructure(
	ctx context.Context,
	sup *Supervisor,
	gw *Gateway,
	sc *ScalingoClient,
	cf *CloudflareClient,
	initialSC string,
	initialCF string,
	region string,
) {
	for i := 0; i < 40 && !sup.IsReady(); i++ {
		if !sleepContext(ctx, 250*time.Millisecond) {
			return
		}
	}

	if !sleepContext(ctx, startupOrchestrationDelay) {
		return
	}

	scalingoDomain := cleanHost(initialSC)
	customDomain := cleanHost(initialCF)
	topologyUpdated := false

	syncDomains := func(newSC, newCF string) {
		cleanSC := cleanHost(newSC)
		cleanCF := cleanHost(newCF)
		if isScalingoPublicDomain(cleanSC) {
			if scalingoDomain == "" || (!isFullScalingoServiceDomain(scalingoDomain) && isFullScalingoServiceDomain(cleanSC)) {
				if scalingoDomain != cleanSC {
					scalingoDomain = cleanSC
					topologyUpdated = true
				}
			}
		}
		if cleanCF != "" && !isScalingoManagedDomain(cleanCF) {
			if customDomain == "" || strings.HasSuffix(cleanCF, "."+customDomain) {
				if customDomain != cleanCF {
					customDomain = cleanCF
					topologyUpdated = true
				}
			}
		}
		sup.SetInfrastructureDomains(scalingoDomain, customDomain, region)
		gw.SetInfrastructureDomains(scalingoDomain, customDomain, region)
		if cf != nil {
			if scalingoDomain != "" {
				cf.SetScalingoOrigin(scalingoDomain)
			}
			if customDomain != "" {
				cf.SetPreferredDomain(customDomain)
			}
		}
		if sc != nil {
			if scalingoDomain != "" {
				sc.SetServiceDomain(scalingoDomain)
			}
			if customDomain != "" {
				sc.SetCustomDomain(customDomain)
			}
		}
	}

	if sc != nil && sc.IsConfigured() {
		// Scalingo supports Zero-Restart variable persistence: updating variables does not interrupt running containers
		if (sup.IsMasterKeyAutoGenerated() || sanitizeMasterKey(getEnv("BERMUDA_MASTER_KEY", getEnv("MASTER_KEY", ""))) == "") &&
			!strings.EqualFold(getEnv("BERMUDA_PERSIST_KEY", "true"), "false") {
			sc.PersistMasterKey(ctx, sup.MasterKey())
		}

		if srvDom, err := sc.EnsureServiceDomain(ctx); err == nil && srvDom != "" {
			syncDomains(srvDom, "")
		} else if err != nil {
			log.Printf("[Scalingo] Notice: Service domain lookup: %v", err)
		}
		if reg := sc.GetDiscoveredRegion(); reg != "" {
			region = normalizeRegion(reg)
			sup.SetInfrastructureDomains(scalingoDomain, customDomain, region)
			gw.SetInfrastructureDomains(scalingoDomain, customDomain, region)
		}
	}

	if cf != nil && cf.Token != "" {
		probeCtx, probeCancel := context.WithTimeout(ctx, 12*time.Second)
		if cfDom, err := cf.FetchZoneDomain(probeCtx); err == nil && cfDom != "" {
			syncDomains(cf.GetScalingoOrigin(), cfDom)
		} else if err != nil {
			log.Printf("[Cloudflare] Notice: Zone domain discovery: %v", err)
		}
		probeCancel()
	}

	var customDomInfo *ScalingoCustomDomainInfo
	var cnameRecordID string

	if customDomain != "" && (sc != nil || scalingoDomain != "") {
		if sc != nil && sc.IsConfigured() {
			info, err := sc.EnsureCustomDomain(ctx, customDomain)
			if err != nil {
				log.Printf("[Scalingo] Notice: Custom domain registration (%s): %v", customDomain, err)
			} else if info != nil {
				customDomInfo = info
				syncDomains(sc.GetServiceDomain(), info.Domain)
			}
		}
		if customDomInfo == nil && scalingoDomain != "" {
			certState := "pending_dns"
			if probeCustomDomainTLS(ctx, customDomain, scalingoDomain) {
				certState = "created"
			}
			customDomInfo = &ScalingoCustomDomainInfo{
				Domain:            customDomain,
				CNAMETarget:       scalingoDomain,
				LetsEncrypt:       certState == "created",
				LetsEncryptStatus: certState,
				CertificateStatus: certState,
			}
		}
		if customDomInfo != nil && cf != nil && cf.Token != "" {
			recID, dnsErr := cf.ProvisionScalingoDNS(ctx, customDomInfo)
			if dnsErr != nil {
				log.Printf("[Cloudflare] Warning: Automated Scalingo DNS provisioning: %v", dnsErr)
			} else {
				cnameRecordID = recID
				_ = sleepContext(ctx, dnsPropagationSettleDelay)
			}
		}
	}

	if cf != nil && cf.Token != "" && ctx.Err() == nil {
		cf.Tune(ctx)
		syncDomains(cf.GetScalingoOrigin(), cf.CachedZoneDomain())
	}

	if cf != nil && customDomInfo != nil && !customDomInfo.IsCertificateValid() && ctx.Err() == nil {
		log.Printf("[Scalingo] Waiting for Let's Encrypt HTTP-01 TLS readiness on %s before enabling Cloudflare Orange Cloud...", customDomInfo.Domain)
		if sc != nil && sc.IsConfigured() {
			updatedInfo, valid := sc.WaitCustomDomainCertificate(ctx, customDomInfo.ID, customDomInfo.Domain, defaultSCCertPollWait)
			if valid && updatedInfo != nil {
				cf.PromoteCustomDomainToOrangeCloud(ctx, updatedInfo.Domain, updatedInfo.CNAMETarget, cnameRecordID)
			} else if ctx.Err() == nil {
				go watchAndPromoteCustomDomain(ctx, sc, cf, customDomInfo, cnameRecordID)
			}
		} else {
			go watchAndPromoteCustomDomain(ctx, nil, cf, customDomInfo, cnameRecordID)
		}
	}

	if sc != nil && sc.IsConfigured() && ctx.Err() == nil {
		sc.TuneComputeAndNetwork(ctx)
	}

	if ctx.Err() == nil && (topologyUpdated || sc != nil || cf != nil) {
		log.Printf("[Runtime] Synchronized Topology: ScalingoDomain=%q | CloudflareDomain=%q | Region=%q",
			scalingoDomain, customDomain, region)
		sup.LogProvisioningLink("")
	}
}

func watchAndPromoteCustomDomain(
	parent context.Context,
	sc *ScalingoClient,
	cf *CloudflareClient,
	info *ScalingoCustomDomainInfo,
	cnameRecordID string,
) {
	ctx, cancel := context.WithTimeout(parent, 15*time.Minute)
	defer cancel()

	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if sc != nil && sc.IsConfigured() {
				latest, err := sc.FetchCustomDomainStatus(ctx, info.ID, info.Domain)
				if err == nil && latest != nil && latest.IsCertificateValid() {
					log.Printf("[Scalingo] ✓ Deferred Let's Encrypt TLS validation completed for %s (%s)",
						latest.Domain, latest.CertificateStatus)
					cf.PromoteCustomDomainToOrangeCloud(ctx, latest.Domain, latest.CNAMETarget, cnameRecordID)
					return
				}
			} else if probeCustomDomainTLS(ctx, info.Domain, info.CNAMETarget) {
				log.Printf("[Scalingo] ✓ Direct OpenResty TLS SNI handshake verified for %s", info.Domain)
				cf.PromoteCustomDomainToOrangeCloud(ctx, info.Domain, info.CNAMETarget, cnameRecordID)
				return
			}
		}
	}
}

func teardown(
	srv *http.Server,
	gw *Gateway,
	sup *Supervisor,
	supCancel context.CancelFunc,
	cloudCancel context.CancelFunc,
	graceful bool,
) {
	// Scalingo enforces a 30-second SIGTERM -> SIGKILL cutoff; 24s guarantees clean exit
	hardDeadline := time.Now().Add(24 * time.Second)

	if cloudCancel != nil {
		cloudCancel()
	}

	gw.SetDraining()
	if graceful {
		log.Println("[Gateway] Stage 1/5: Health status set to 503 (draining)...")
		time.Sleep(drainPropagationWindow)
	}

	if graceful {
		log.Println("[Gateway] Stage 2/5: Draining HTTP listeners and active XHTTP streams...")
		httpDeadline := minTime(hardDeadline.Add(-7*time.Second), time.Now().Add(12*time.Second))
		httpCtx, cancelHTTP := context.WithDeadline(context.Background(), httpDeadline)
		if err := srv.Shutdown(httpCtx); err != nil {
			log.Printf("[Gateway] HTTP drain timeout (%v); closing listener", err)
			_ = srv.Close()
		} else {
			log.Println("[Gateway] HTTP listener drained cleanly")
		}
		cancelHTTP()

		log.Println("[Gateway] Stage 3/5: Waiting for active upgraded WebSocket tunnels...")
		tunnelDeadline := minTime(hardDeadline.Add(-6*time.Second), time.Now().Add(httpDrainTimeout))
		if tunnelDeadline.After(time.Now()) {
			tunnelCtx, cancelTunnel := context.WithDeadline(context.Background(), tunnelDeadline)
			gw.WaitTunnels(tunnelCtx)
			cancelTunnel()
		}
	} else {
		_ = srv.Close()
	}

	log.Println("[Gateway] Stage 4/5: Closing remaining sockets and idle pools...")
	gw.CloseTunnels()
	gw.CloseIdleBackendConns()

	log.Println("[Gateway] Stage 5/5: Stopping worker process group...")
	supCancel()
	remainingSupTime := time.Until(hardDeadline)
	if remainingSupTime <= 0 {
		remainingSupTime = 2 * time.Second
	}
	sup.Stop(remainingSupTime)
}

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	log.Println("[Gateway] Initializing BERMUDA PORTAL Edge Router (Scalingo + Cloudflare Edition)...")

	gwMB, workerMB := deriveMemoryBudget()
	applyMemoryCeiling(gwMB)
	procs := applyGOMAXPROCS()

	_ = syscall.Setenv("BERMUDA_WORKER_MEM_MB", strconv.Itoa(workerMB))
	_ = syscall.Setenv("BERMUDA_WORKER_GOMAXPROCS", strconv.Itoa(procs))
	log.Printf("[Runtime] Dynamic memory ceiling: Gateway=%dMiB, Worker=%dMiB (ContainerSize=%q, GOGC=100) | GOMAXPROCS=%d",
		gwMB, workerMB, getEnv("CONTAINER_SIZE", "auto"), procs)

	sigCtx, stopSig := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stopSig()

	port := getEnv("PORT", defaultPort)
	scalingoDomain, customDomain := resolveInfrastructureDomains()
	region := resolveScalingoRuntimeRegion()

	sup := NewSupervisor()
	if err := sup.PreflightContext(sigCtx); err != nil {
		log.Printf("[Gateway] Notice: Preflight check: %v", err)
	}

	cfToken := sanitizeCloudflareToken(getEnv("CLOUDFLARE_API_TOKEN", getEnv("BERMUDA_CF_API_TOKEN", "")))
	cfZoneID := sanitizeExplicitCredential(getEnv("CLOUDFLARE_ZONE_ID", getEnv("BERMUDA_CF_ZONE_ID", "")))
	var cf *CloudflareClient
	if cfToken != "" {
		cf = NewCloudflareClient(cfToken, cfZoneID)
		if scalingoDomain != "" {
			cf.SetScalingoOrigin(scalingoDomain)
		}
		if customDomain != "" {
			cf.SetPreferredDomain(customDomain)
		}
	} else {
		log.Println("[Cloudflare] Notice: CLOUDFLARE_API_TOKEN unset. Edge auto-tuning bypassed.")
	}

	scToken := sanitizeScalingoToken(getEnv("SCALINGO_API_TOKEN", getEnv("SCALINGO_TOKEN", getEnv("BERMUDA_SCALINGO_TOKEN", ""))))
	var sc *ScalingoClient
	if scToken != "" {
		sc = NewScalingoClient(scToken)
		if scalingoDomain != "" {
			sc.SetServiceDomain(scalingoDomain)
		}
		if customDomain != "" {
			sc.SetCustomDomain(customDomain)
		}
	} else {
		log.Println("[Scalingo] Notice: SCALINGO_API_TOKEN unset. Scalingo API self-provisioning bypassed.")
	}

	sup.SetInfrastructureDomains(scalingoDomain, customDomain, region)
	primaryLogDomain := customDomain
	if primaryLogDomain == "" {
		primaryLogDomain = scalingoDomain
	}
	if primaryLogDomain != "" {
		sup.SetPublicDomain(primaryLogDomain)
	}

	log.Printf("[Runtime] Initial Topology: ScalingoDomain=%q | CloudflareDomain=%q | Region=%q",
		scalingoDomain, customDomain, region)

	gw := NewGateway(sup, cf, scalingoDomain, customDomain, region)
	gw.SetScalingoClient(sc)

	topologyUpdater := func(scDom, cfDom string) {
		sup.SetInfrastructureDomains(scDom, cfDom, region)
		gw.SetInfrastructureDomains(scDom, cfDom, region)
	}
	if cf != nil {
		cf.SetTopologyCallback(topologyUpdater)
	}
	if sc != nil {
		sc.SetTopologyCallback(topologyUpdater)
	}

	supCtx, supCancel := context.WithCancel(context.Background())
	supErrCh := make(chan error, 1)
	go func() {
		supErrCh <- sup.Run(supCtx)
	}()

	srv := &http.Server{
		Addr:              "0.0.0.0:" + port,
		Handler:           gw.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       0,
		WriteTimeout:      0,
		IdleTimeout:       serverIdleTimeout,
		MaxHeaderBytes:    32 << 10,
		ConnState:         gw.TrackConnState,
	}

	listenCfg := net.ListenConfig{
		KeepAliveConfig: net.KeepAliveConfig{
			Enable:   true,
			Idle:     edgeKeepAlivePeriod,
			Interval: edgeKeepAlivePeriod,
			Count:    4,
		},
		Control: func(network, address string, c syscall.RawConn) error {
			var controlErr error
			err := c.Control(func(fd uintptr) {
				if e := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpUserTimeoutOpt, 90000); e != nil {
					controlErr = e
				}
			})
			if err != nil {
				return err
			}
			return controlErr
		},
	}

	ln, err := listenCfg.Listen(context.Background(), "tcp", srv.Addr)
	if err != nil {
		log.Fatalf("[Gateway] Fatal: Cannot bind listener on %s: %v", srv.Addr, err)
	}

	serverErrCh := make(chan error, 1)
	go func() {
		log.Printf("[Gateway] Edge listener active on %s (PID %d, Container=%q, GOMAXPROCS=%d)",
			srv.Addr, os.Getpid(), getEnv("CONTAINER", "web-1"), procs)
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrCh <- err
		}
	}()

	cloudCtx, cloudCancel := context.WithCancel(sigCtx)
	defer cloudCancel()
	if sc != nil || cf != nil {
		go orchestrateCloudInfrastructure(cloudCtx, sup, gw, sc, cf, scalingoDomain, customDomain, region)
	}

	select {
	case err := <-serverErrCh:
		log.Printf("[Gateway] Fatal: HTTP server error: %v", err)
		teardown(srv, gw, sup, supCancel, cloudCancel, false)
		os.Exit(1)
	case err := <-supErrCh:
		if err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("[Gateway] Fatal: Worker supervisor halted: %v", err)
		}
		teardown(srv, gw, sup, supCancel, cloudCancel, false)
		os.Exit(1)
	case <-sigCtx.Done():
		log.Println("[Gateway] Termination signal (SIGTERM/SIGINT) received. Initiating 24s graceful drain...")
	}

	teardown(srv, gw, sup, supCancel, cloudCancel, true)
	log.Println("[Gateway] BERMUDA PORTAL Edge Router shutdown complete. Exit 0.")
}
