package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	gohttp "net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

type TokenCollector struct {
	mu       sync.Mutex
	progress int
	total    int
	done     bool
	stopped  bool

	reqRunning  bool
	reqResults  chan ReqResult
	tokenCount  int
	requestRate int
}

type TokenInfo struct {
	Cookies   string    `json:"cookies"`
	UserAgent string    `json:"user_agent"`
	Proxy     string    `json:"proxy"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type StartTestReq struct {
	ConcurrentRequests int    `json:"concurrent_requests"`
	TotalRequests      int    `json:"total_requests"`
	URL                string `json:"url"`
}

type FrontendResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Data    string `json:"data,omitempty"`
}

type WSMessage struct {
	Type    string `json:"type"`
	Message string `json:"message"`
	Time    string `json:"time"`
	Level   string `json:"level"`
}

type ContainerResult struct {
	Success      bool   `json:"success"`
	Cookies      string `json:"cookies"`
	UserAgent    string `json:"userAgent"`
	HasClearance bool   `json:"hasClearance"`
	HasCFBM      bool   `json:"hasCFBM"`
	Proxy        string `json:"proxy"`
	Error        string `json:"error"`
}

type ReqResult struct {
	Success bool
	Status  int
	Body    string
	Error   string
}

type Application struct {
	upgrader      websocket.Upgrader
	collector     *TokenCollector
	wsConnections map[*websocket.Conn]bool
	wsMutex       sync.Mutex
	proxyList     []string
	proxyCounter  int
	proxyMutex    sync.Mutex
}

func NewApplication() *Application {
	return &Application{
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *gohttp.Request) bool {
				return true
			},
		},
		collector: &TokenCollector{
			progress: 0,
			total:    0,
			done:     false,
			stopped:  false,
		},
		wsConnections: make(map[*websocket.Conn]bool),
		proxyList: []string{
			"http://wapim_proxy:wapim@37.48.78.144:9000",
			"http://wapim_user:wapim_password@195.46.147.233:64200",
			"http://wapim_user:wapim_password@195.87.209.226:8888",
			"http://wapim_user:wapim_password@84.44.15.231:8888",
			"http://wapim_user:wapim_password@84.44.17.234:8888",
			"http://wapim_user:wapim_password@195.87.79.147:8888",
		},
		proxyCounter: 0,
	}
}

func (app *Application) getNextProxy() string {
	app.proxyMutex.Lock()
	defer app.proxyMutex.Unlock()

	if len(app.proxyList) == 0 {
		return ""
	}

	proxy := app.proxyList[app.proxyCounter%len(app.proxyList)]
	app.proxyCounter++
	return proxy
}

func (app *Application) Run() {
	r := mux.NewRouter()

	r.PathPrefix("/static/").Handler(gohttp.StripPrefix("/static/", gohttp.FileServer(gohttp.Dir("static"))))

	// r.HandleFunc("/api/collect-tokens", app.handleCollectTokens).Methods("POST")
	r.HandleFunc("/api/stop-collection", app.handleStopCollection).Methods("POST")
	r.HandleFunc("/api/test", app.handleTest).Methods("POST")
	r.HandleFunc("/api/stop-test", app.handleStopTest).Methods("POST")
	r.HandleFunc("/api/token-count", app.handleTokenCount).Methods("GET")
	r.HandleFunc("/api/request-rate", app.handleRequestRate).Methods("GET")
	r.HandleFunc("/ws", app.handleWebSocket)

	r.HandleFunc("/", func(w gohttp.ResponseWriter, r *gohttp.Request) {
		gohttp.ServeFile(w, r, "static/index.html")
	})

	go app.startContinuousTokenCollection()
	go app.startContinuousTokenCleanup()

	fmt.Println("Server starting on :8080")
	log.Fatal(gohttp.ListenAndServe(":8080", r))
}

func (app *Application) handleTest(w gohttp.ResponseWriter, r *gohttp.Request) {
	var req StartTestReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		gohttp.Error(w, "Invalid request", gohttp.StatusBadRequest)
		return
	}

	tokens := app.loadTokensFromResults()
	if len(tokens) == 0 {
		json.NewEncoder(w).Encode(FrontendResponse{
			Success: false,
			Message: "No tokens available",
		})
		return
	}

	go app.runDynamicTest(req.TotalRequests, req.URL)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(FrontendResponse{
		Success: true,
		Message: "Dynamic test started (speed based tokens)",
	})
}

func (app *Application) handleStopTest(w gohttp.ResponseWriter, r *gohttp.Request) {
	app.collector.mu.Lock()
	app.collector.reqRunning = false
	app.collector.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(FrontendResponse{
		Success: true,
		Message: "Dynamic test stopped.",
	})
}

func (app *Application) handleStopCollection(w gohttp.ResponseWriter, r *gohttp.Request) {
	app.collector.mu.Lock()
	app.collector.stopped = true
	app.collector.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(FrontendResponse{
		Success: true,
		Message: "Token collection stopped.",
	})
}

func (app *Application) startContinuousTokenCollection() {
	url := "https://verrado.ezlinksgolf.com"
	batchSize := 10

	for {
		app.collector.mu.Lock()
		stopped := app.collector.stopped
		app.collector.mu.Unlock()

		if stopped {
			log.Println("Token collection stopped")
			break
		}

		log.Printf("Starting batch of %d containers\n", batchSize)
		done := app.collectTokensFromDocker(batchSize, url)
		<-done
		log.Printf("Batch completed\n")
	}
}

// Remove expired tokens (max 4 minute)
func (app *Application) startContinuousTokenCleanup() {
	for {
		time.Sleep(10 * time.Second)

		resultsDir := "./results"
		tokensFile := filepath.Join(resultsDir, "tokens.json")

		var tokens []TokenInfo
		if data, err := ioutil.ReadFile(tokensFile); err != nil {
			log.Printf("I couldn't read token file: %v", err)
			continue
		} else {
			if err := json.Unmarshal(data, &tokens); err != nil {
				log.Printf("Token JSON parse error: %v", err)
				continue
			}
		}

		if len(tokens) == 0 {
			continue
		}

		var validTokens []TokenInfo
		expiredCount := 0
		now := time.Now()

		for _, token := range tokens {
			if now.Before(token.ExpiresAt) {
				validTokens = append(validTokens, token)
			} else {
				expiredCount++
			}
		}

		if expiredCount > 0 {
			data, err := json.MarshalIndent(validTokens, "", "  ")
			if err != nil {
				log.Printf("Error marshaling tokens: %v", err)
				continue
			}

			err = ioutil.WriteFile(tokensFile, data, 0644)
			if err != nil {
				log.Printf("Error saving tokens: %v", err)
				continue
			}

			log.Printf("%d expired token deleted, %d valid token remaining", expiredCount, len(validTokens))
		} else {
			log.Printf("Token cleanup executed - %d token valid", len(tokens))
		}
	}
}

func (app *Application) handleRequestRate(w gohttp.ResponseWriter, r *gohttp.Request) {
	app.collector.mu.Lock()
	rate := app.collector.requestRate
	app.collector.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"rate": rate,
		"time": time.Now().Format("15:04:05"),
	})
}

func (app *Application) handleTokenCount(w gohttp.ResponseWriter, r *gohttp.Request) {
	resultsDir := "./results"
	tokensFile := filepath.Join(resultsDir, "tokens.json")
	now := time.Now()

	var validTokens []TokenInfo
	if data, err := ioutil.ReadFile(tokensFile); err == nil {
		var tokenInfos []TokenInfo
		if err := json.Unmarshal(data, &tokenInfos); err == nil {
			for _, token := range tokenInfos {
				if now.Before(token.ExpiresAt) {
					validTokens = append(validTokens, token)
				}
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"count":       len(validTokens),
		"last_update": now.Format("15:04:05"),
	})
}

func (app *Application) removeTokenFromFile(tokenToRemove TokenInfo) {
	resultsDir := "./results"
	tokensFile := filepath.Join(resultsDir, "tokens.json")

	var tokens []TokenInfo
	if data, err := ioutil.ReadFile(tokensFile); err == nil {
		if err := json.Unmarshal(data, &tokens); err == nil {
			var newTokens []TokenInfo
			for _, token := range tokens {
				if token.Cookies != tokenToRemove.Cookies {
					newTokens = append(newTokens, token)
				}
			}

			if newData, err := json.MarshalIndent(newTokens, "", "  "); err == nil {
				if err := ioutil.WriteFile(tokensFile, newData, 0644); err == nil {
					app.logWarningWithBroadcast("Token deleted: %s... (Probably cloudflare)",
						tokenToRemove.Cookies[:50])
				}
			}
		}
	}
}

func (app *Application) handleWebSocket(w gohttp.ResponseWriter, r *gohttp.Request) {
	conn, err := app.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	app.wsMutex.Lock()
	app.wsConnections[conn] = true
	app.wsMutex.Unlock()

	logMsg := WSMessage{
		Type:    "log",
		Message: "Websocket connected, please wait for logs.",
		Time:    time.Now().Format("15:04:05"),
		Level:   "info",
	}
	conn.WriteJSON(logMsg)

	defer func() {
		app.wsMutex.Lock()
		delete(app.wsConnections, conn)
		app.wsMutex.Unlock()
	}()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// TODO: Send some progress for reporting.
		}
	}
}

func (app *Application) runDynamicTest(totalRequests int, url string) {
	app.logSuccessWithBroadcast("Dynamic test startinh: %d request, URL: %s", totalRequests, url)

	app.broadcastLog("Test started - Dynamic rate active", "info")

	app.collector.mu.Lock()
	app.collector.reqRunning = true
	app.collector.reqResults = make(chan ReqResult, totalRequests)
	app.collector.requestRate = 3 // Default 3 req rate
	app.collector.mu.Unlock()

	// Prepare static payload. Just test
	payload := []byte(`{
		"p01": [4977, 24734],
		"p02": "08/07/2025",
		"p03": "5:00 AM",
		"p04": "7:00 PM",
		"p05": 0,
		"p06": 4,
		"p07": false
	}`)

	// Start request rate controller
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			app.collector.mu.Lock()
			if !app.collector.reqRunning { // when stop-request triggerd
				app.collector.mu.Unlock()
				return
			}

			// Speed rate based active token
			tokens := app.loadTokensFromResults()
			tokenCount := len(tokens)
			app.collector.tokenCount = tokenCount

			if tokenCount == 0 {
				app.collector.requestRate = 0
			} else if tokenCount < 5 {
				app.collector.requestRate = 1
			} else if tokenCount < 20 {
				app.collector.requestRate = 2
			} else if tokenCount < 40 {
				app.collector.requestRate = 4
			} else if tokenCount < 60 {
				app.collector.requestRate = 6
			} else if tokenCount < 80 {
				app.collector.requestRate = 8
			} else if tokenCount < 100 {
				app.collector.requestRate = 20
			} else if tokenCount < 150 {
				app.collector.requestRate = 30
			} else {
				app.collector.requestRate = 40
			}

			// force req rate. just testing
			app.collector.requestRate = 50

			app.logWithBroadcast(" Dynamic rate active: %d tokens, req rate: %d req/sec", tokenCount, app.collector.requestRate)
			app.collector.mu.Unlock()
		}
	}()

	requestID := 0
	for requestID < totalRequests {
		app.collector.mu.Lock()
		if !app.collector.reqRunning {
			app.collector.mu.Unlock()
			break
		}
		rate := app.collector.requestRate
		app.collector.mu.Unlock()

		if rate > 0 {
			go func(id int) {
				result := app.makeDynamicRequest(url, payload, id)

				if result.Success {
					app.logWithBroadcast("Request %d result: %s", id, result.Body[:app.min(len(result.Body), 500)])
				} else {
					app.logErrorWithBroadcast(" Request %d failed: %s", id, result.Error)
				}

				app.collector.reqResults <- result
			}(requestID)
			requestID++
		}

		// Wait depend current rate
		if rate > 0 {
			time.Sleep(time.Duration(1000/rate) * time.Millisecond)
		} else {
			// Wait when no tokens
			time.Sleep(1 * time.Second)
		}
	}

	// Wait for all requests to complete
	completed := 0
	successCount := 0
	errorCount := 0

	for completed < totalRequests {
		select {
		case result := <-app.collector.reqResults:
			completed++
			if result.Success {
				successCount++
			} else {
				errorCount++
			}
			app.logWithBroadcast("Test progress: %d/%d completed (Success: %d, Error: %d)", completed, totalRequests, successCount, errorCount)
		}
	}

	app.logSuccessWithBroadcast("Dynamic test completed. Success: %d, Error: %d", successCount, errorCount)

	app.collector.mu.Lock()
	app.collector.reqRunning = false
	app.collector.mu.Unlock()
}

func (app *Application) makeDynamicRequest(baseURL string, payload []byte, requestID int) ReqResult {
	tokens := app.loadTokensFromResults()
	if len(tokens) == 0 {
		app.logErrorWithBroadcast("Request %d: No tokens available", requestID)
		return ReqResult{
			Success: false,
			Error:   "No tokens available",
		}
	}

	// round-robin based
	token := tokens[requestID%len(tokens)]

	options := []tls_client.HttpClientOption{
		tls_client.WithClientProfile(profiles.Chrome_131), // sometime 131 sometime 133.
		tls_client.WithTimeoutSeconds(30),
	}

	if proxy := token.Proxy; proxy != "" {
		options = append(options, tls_client.WithProxyUrl(proxy))
		app.logWithBroadcast("Using proxy: %s", proxy)
	}

	client, err := tls_client.NewHttpClient(tls_client.NewLogger(), options...)
	if err != nil {
		app.logErrorWithBroadcast("I couldn't create TLS client: %v", err)
		return ReqResult{
			Success: false,
			Error:   fmt.Sprintf("I couldn't create TLS client: %v", err),
		}
	}

	req, err := fhttp.NewRequest(fhttp.MethodPost, fmt.Sprintf("%s/api/search/search", baseURL), bytes.NewReader(payload))
	if err != nil {
		app.logErrorWithBroadcast("Request %d: I couldn't prepare request: %v", requestID, err)
		return ReqResult{
			Success: false,
			Error:   fmt.Sprintf("I couldn't prepare request: %v", err),
		}
	}

	req.Header = fhttp.Header{
		"accept":                      {"application/json, text/plain, */*"},
		"accept-language":             {"en-US,en;q=0.9,tr;q=0.8,tr-TR;q=0.7"},
		"cache-control":               {"no-cache"},
		"content-type":                {"application/json; charset=UTF-8"},
		"origin":                      {baseURL},
		"pragma":                      {"no-cache"},
		"priority":                    {"u=1, i"},
		"referer":                     {fmt.Sprintf("%s/index.html", baseURL)},
		"sec-ch-ua":                   {`"Not)A;Brand";v="8", "Chromium";v="138", "Google Chrome";v="138"`},
		"sec-ch-ua-arch":              {`"arm"`},
		"sec-ch-ua-bitness":           {`"64"`},
		"sec-ch-ua-full-version":      {`"138.0.7204.184"`},
		"sec-ch-ua-full-version-list": {`"Not)A;Brand";v="8.0.0.0", "Chromium";v="138.0.7204.184", "Google Chrome";v="138.0.7204.184"`},
		"sec-ch-ua-mobile":            {"?0"},
		"sec-ch-ua-model":             {`""`},
		"sec-ch-ua-platform":          {`"macOS"`},
		"sec-ch-ua-platform-version":  {`"15.1.0"`},
		"sec-fetch-dest":              {"empty"},
		"sec-fetch-mode":              {"cors"},
		"sec-fetch-site":              {"same-origin"},
		"user-agent":                  {token.UserAgent},
		"cookie":                      {token.Cookies},
	}

	resp, err := client.Do(req)
	if err != nil {
		app.logErrorWithBroadcast("Request %d: I couldn't send request: %v", requestID, err)
		return ReqResult{
			Success: false,
			Error:   fmt.Sprintf("I couldn't send request: %v", err),
		}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		app.logErrorWithBroadcast("Request %d: I couldn't read body: %v", requestID, err)
		return ReqResult{
			Success: false,
			Error:   fmt.Sprintf("I couldn't read body: %v", err),
		}
	}

	// immediatly, without defer. Because we don't have time.
	resp.Body.Close()

	success := resp.StatusCode >= 200 && resp.StatusCode < 300

	// if response is cloudflare (failed token)
	if !success || strings.Contains(string(body), "<title>Just a moment...</title>") ||
		strings.Contains(string(body), "cloudflare") ||
		strings.Contains(string(body), "cf-browser-verification") {

		tokenToRemove := TokenInfo{
			Cookies:   token.Cookies,
			UserAgent: token.UserAgent,
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(4 * time.Minute),
		}

		// Remove the failed token
		app.removeTokenFromFile(tokenToRemove)

		app.logErrorWithBroadcast("Request %d: Token unsuccessful - Cloudflare challenge detected, token removed", requestID)
	}

	return ReqResult{
		Success: success,
		Status:  resp.StatusCode,
		Body:    string(body),
		Error:   fmt.Sprintf("Status: %d, Body: %s", resp.StatusCode, string(body[:app.min(len(body), 100)])),
	}
}

func (app *Application) broadcastLog(message string, level string) {
	logMsg := WSMessage{
		Type:    "log",
		Message: message,
		Time:    time.Now().Format("15:04:05"),
		Level:   level,
	}

	app.wsMutex.Lock()
	defer app.wsMutex.Unlock()

	for conn := range app.wsConnections {
		if err := conn.WriteJSON(logMsg); err != nil {
			log.Printf("WebSocket log write error: %v", err)
			delete(app.wsConnections, conn)
			conn.Close()
		}
	}
}

func (app *Application) logWithBroadcast(format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	log.Print(message)
	app.broadcastLog(message, "info")
}

func (app *Application) logErrorWithBroadcast(format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	log.Printf("[ ERROR ] %s", message)
	app.broadcastLog("[ ERROR ]"+message, "error")
}

// logSuccessWithBroadcast logs success to console and broadcasts to WebSocket clients
func (app *Application) logSuccessWithBroadcast(format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	log.Printf("[ SUCCESS ] %s", message)
	app.broadcastLog("[ SUCCESS ]"+message, "success")
}

// logWarningWithBroadcast logs warning to console and broadcasts to WebSocket clients
func (app *Application) logWarningWithBroadcast(format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	log.Printf("[ WARNING ] %s", message)
	app.broadcastLog("[ WARNING ] "+message, "warning")
}

func (app *Application) generateRandomContainerName() string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	const length = 8
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}

	return fmt.Sprintf("token-collector-%s", string(b))
}

func (app *Application) collectTokensFromDocker(concurrentCount int, url string) chan bool {
	done := make(chan bool, 1)

	go func() {
		defer func() {
			done <- true
			close(done)
		}()

		log.Printf("collectTokensFromDocker called with concurrentCount -> %d, url -> %s", concurrentCount, url)

		resultsDir := "./results"
		if err := os.MkdirAll(resultsDir, 0755); err != nil {
			log.Printf("Creating results directory err: %v", err)
			return
		}

		totalRequests := concurrentCount
		containersPerBatch := concurrentCount
		if containersPerBatch > 10 {
			containersPerBatch = 10 // Max 10 containers per batch
		}
		totalBatches := (totalRequests + containersPerBatch - 1) / containersPerBatch

		for batch := 0; batch < totalBatches; batch++ {
			remainingTokens := totalRequests - batch*containersPerBatch
			currentBatchSize := containersPerBatch
			if remainingTokens < containersPerBatch {
				currentBatchSize = remainingTokens
			}

			// Start containers for this batch
			var wg sync.WaitGroup
			results := make(chan ContainerResult, currentBatchSize)

			for i := 0; i < currentBatchSize; i++ {
				wg.Add(1)
				go func(containerID int) {
					defer wg.Done()
					result := app.runDockerContainer(containerID, url)
					results <- result
				}(batch*containersPerBatch + i + 1)
			}

			wg.Wait()
			close(results)

			successCount := 0
			for result := range results {
				if result.Success {
					app.collector.mu.Lock()
					app.collector.progress++
					app.collector.mu.Unlock()
					successCount++

					log.Printf("Save token %d with result: %+v", batch*containersPerBatch+successCount, result)
					app.saveTokenResult(result, batch*containersPerBatch+successCount)
				} else {
					log.Printf("Container failed: %s", result.Error)
				}
			}

			log.Printf("Batch %d completed: %d/%d successfuly", batch+1, successCount, currentBatchSize)

			// Small delay between batches
			//if batch < totalBatches-1 {
			//	time.Sleep(2 * time.Second)
			//}
		}

		app.collector.mu.Lock()
		app.collector.done = true
		app.collector.mu.Unlock()

		log.Printf("Token collected completed")
	}()

	return done
}

func (app *Application) runDockerContainer(containerID int, url string) ContainerResult {
	log.Printf("Container %d starting. URL: %s", containerID, url)

	containerName := app.generateRandomContainerName()

	proxy := app.getNextProxy()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	args := []string{"run",
		"--name", containerName,
		"--env", fmt.Sprintf("TARGET_URL=%s", url),
		"--env", fmt.Sprintf("CONTAINER_ID=%d", containerID), // Just metadata
		"--volume", "./results:/app/results",
	}

	if proxy != "" {
		args = append(args,
			"--env", fmt.Sprintf("HTTP_PROXY=%s", proxy),
			"--env", fmt.Sprintf("HTTPS_PROXY=%s", proxy))
		log.Printf("Container %d using proxy: %s", containerID, proxy)
	}

	// TODO: Maybe we can inject from ENV
	args = append(args, "doscrape-token-collector")

	cmd := exec.CommandContext(ctx, "docker", args...)

	output, err := cmd.CombinedOutput()

	cleanupCmd := exec.Command("docker", "rm", "-f", containerName)
	cleanupCmd.Run()

	if err != nil {
		log.Printf("Container %d failed: %v output: %s", containerID, err, output)
		return ContainerResult{
			Success: false,
			Error:   fmt.Sprintf("Container execution failed: %v", err),
		}
	}

	outputStr := string(output)
	log.Printf("Container %d output: %s", containerID, outputStr)

	// Extract json from container stdout.
	var result ContainerResult
	lines := strings.Split(outputStr, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Check "{" or "}"
		if strings.HasPrefix(line, "{") && strings.HasSuffix(line, "}") {
			if err := json.Unmarshal([]byte(line), &result); err == nil {
				return result
			} else {
				log.Printf("JSON parse error: %v", err)
			}
		}
	}

	jsonStart := strings.LastIndex(outputStr, "{")
	jsonEnd := strings.LastIndex(outputStr, "}")

	if jsonStart != -1 && jsonEnd != -1 && jsonEnd > jsonStart {
		jsonStr := outputStr[jsonStart : jsonEnd+1]
		log.Printf("Trying to extract JSON: %s", jsonStr)
		if err := json.Unmarshal([]byte(jsonStr), &result); err == nil {
			log.Printf("Container %d completed successfully", containerID)
			return result
		} else {
			log.Printf("Extracted JSON parse error: %v", err)
		}
	}

	return ContainerResult{
		Success: false,
		Error:   "No valid JSON result found in container output",
	}
}

func (app *Application) saveTokenResult(result ContainerResult, tokenID int) {
	log.Printf("saveTokenResult called with tokenID -> %d, result.Success -> %v", tokenID, result.Success)

	resultsDir := "./results"
	tokensFile := filepath.Join(resultsDir, "tokens.json")

	now := time.Now()
	expiresAt := now.Add(4 * time.Minute) // Testlere göre cookieler max 4.30 dakika geçerli kalıyor.

	tokenInfo := TokenInfo{
		Cookies:   result.Cookies,
		UserAgent: result.UserAgent,
		Proxy:     result.Proxy,
		CreatedAt: now,
		ExpiresAt: expiresAt,
	}

	log.Printf("Saving token %d with new format: cookies -> %s, userAgent -> %s, expiresAt-> %s", tokenID, result.Cookies[:50]+"...", result.UserAgent[:50]+"...", expiresAt.Format("15:04:05"))

	var tokens []TokenInfo
	if data, err := ioutil.ReadFile(tokensFile); err == nil {
		if err := json.Unmarshal(data, &tokens); err != nil {
			log.Printf("Existing tokens JSON parse error: %v", err)
			tokens = []TokenInfo{}
		}
	}

	tokens = append(tokens, tokenInfo)

	data, err := json.MarshalIndent(tokens, "", "  ")
	if err != nil {
		log.Printf("Tokens JSON marshal error: %v", err)
		return
	}

	if err := ioutil.WriteFile(tokensFile, data, 0644); err != nil {
		log.Printf("Token file write error: %v", err)
		return
	}

	log.Printf("Token %d saved: tokens.json (expires at %s, total tokens: %d)\n", tokenID, expiresAt.Format("15:04:05"), len(tokens))
}

func (app *Application) loadTokensFromResults() []ContainerResult {
	resultsDir := "./results"
	tokensFile := filepath.Join(resultsDir, "tokens.json")
	tokens := make([]ContainerResult, 0)
	now := time.Now()

	data, err := ioutil.ReadFile(tokensFile)
	if err != nil {
		log.Printf("tokens.json read error: %v", err)
		return tokens
	}

	// Parse tokens array
	var tokenInfos []TokenInfo
	if err := json.Unmarshal(data, &tokenInfos); err != nil {
		log.Printf("tokens.json JSON parse error: %v", err)
		return tokens
	}

	var validTokens []TokenInfo
	var hasExpiredTokens bool

	for _, tokenInfo := range tokenInfos {
		if now.After(tokenInfo.ExpiresAt) {
			log.Printf("Token expired: %s (expired at %s)", tokenInfo.Cookies[:50]+"...", tokenInfo.ExpiresAt.Format("15:04:05"))
			hasExpiredTokens = true
			continue
		}

		validTokens = append(validTokens, tokenInfo)
	}

	if hasExpiredTokens {
		log.Printf("%d expired token deleted, remainiing %d valid token ", len(tokenInfos)-len(validTokens), len(validTokens))

		if data, err := json.MarshalIndent(validTokens, "", "  "); err == nil {
			if err := ioutil.WriteFile(tokensFile, data, 0644); err != nil {
				log.Printf("Updated tokens.json write hatası: %v", err)
			}
		}
	}

	for _, tokenInfo := range validTokens {
		result := ContainerResult{
			Success:   true,
			Cookies:   tokenInfo.Cookies,
			UserAgent: tokenInfo.UserAgent,
			Proxy:     tokenInfo.Proxy,
		}
		tokens = append(tokens, result)
	}

	log.Printf("📂 %d valid token loaded\n", len(tokens))
	return tokens
}

func (app *Application) min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

func main() {
	//app.test()
	//return

	soft, hard, err := SetRlimitMax(0)
	if err != nil {
		log.Panicf("Failed to set NOFILE: %v", err)
	}

	log.Printf("Using max nofile soft -> %d hard -> %d", soft, hard)

	app := NewApplication()
	app.Run()
}
