package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/gorilla/websocket"
)

// ======================== Config Structs ========================

type AppConfig struct {
	Servers         []ServerConfig `json:"servers"`
	CurrentServerID string         `json:"current_server_id"`
}

type ServerConfig struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	ServerAddr  string `json:"server"`  // -f
	ListenAddr  string `json:"listen"`  // -l
	Token       string `json:"token"`   // -token
	ServerIP    string `json:"ip"`      // -ip
	DNSServer   string `json:"dns"`     // -dns
	ECHDomain   string `json:"ech"`     // -ech
	RoutingMode string `json:"routing"` // global, bypass_cn, none
}

// ======================== Runtime State ========================

var (
	logType      = binding.NewString()
	proxyRunning = binding.NewBool()
	
	// Stats Binding
	statusLabel  = binding.NewString()
	speedUpload  = binding.NewString()
	speedDownload = binding.NewString()
	latencyShow   = binding.NewString()

	// Traffic Counters (Atomic)
	totalUp   uint64
	totalDown uint64

	activeConfig ServerConfig

	proxyListener net.Listener
	proxyContext  context.Context
	proxyCancel   context.CancelFunc

	echListMu sync.RWMutex
	echList   []byte

	chinaIPRangesMu sync.RWMutex
	chinaIPRanges   []ipRange

	systemProxyEnabled bool
)

type ipRange struct {
	start uint32
	end   uint32
}

// ======================== GUI Main ========================

func main() {
	os.Setenv("FYNE_SCALE", "1")

	myApp := app.NewWithID("com.echworkers.client")
	myApp.Settings().SetTheme(theme.LightTheme())

	w := myApp.NewWindow("ECH Client Pro")
	w.Resize(fyne.NewSize(900, 750))
	w.CenterOnScreen()

	config := loadConfig()
	if len(config.Servers) == 0 {
		config.Servers = append(config.Servers, ServerConfig{
			ID: "default", Name: "Default Profile", ServerAddr: "example.workers.dev:443",
			ListenAddr: "127.0.0.1:30000", ECHDomain: "cloudflare-ech.com", RoutingMode: "bypass_cn",
		})
		config.CurrentServerID = "default"
	}

	// --- Stats Monitor ---
	statusLabel.Set("Status: Stopped")
	speedUpload.Set("Up: 0 KB/s")
	speedDownload.Set("Down: 0 KB/s")
	latencyShow.Set("Latency: - ms")

	go startSpeedMonitor()

	// --- UI Components ---
	serverCombo := widget.NewSelect([]string{}, nil)
	refreshServerCombo(serverCombo, config)

	nameEntry := widget.NewEntry()
	addrEntry := widget.NewEntry()
	addrEntry.SetPlaceHolder("workers.dev:443")
	listenEntry := widget.NewEntry()
	listenEntry.SetPlaceHolder("127.0.0.1:30000")
	tokenEntry := widget.NewPasswordEntry()
	ipEntry := widget.NewEntry()
	ipEntry.SetPlaceHolder("Preferred IP (Optional)")
	dnsEntry := widget.NewEntry()
	dnsEntry.SetPlaceHolder("DoH Address")
	echEntry := widget.NewEntry()
	echEntry.SetPlaceHolder("ECH Domain")

	routingSelect := widget.NewSelect([]string{"Global Proxy", "Bypass Mainland China", "Direct (None)"}, nil)

	fillForm := func(s ServerConfig) {
		nameEntry.SetText(s.Name)
		addrEntry.SetText(s.ServerAddr)
		listenEntry.SetText(s.ListenAddr)
		tokenEntry.SetText(s.Token)
		ipEntry.SetText(s.ServerIP)
		dnsEntry.SetText(s.DNSServer)
		echEntry.SetText(s.ECHDomain)
		mode := "Global Proxy"
		if s.RoutingMode == "bypass_cn" {
			mode = "Bypass Mainland China"
		}
		if s.RoutingMode == "none" {
			mode = "Direct (None)"
		}
		routingSelect.SetSelected(mode)
	}

	getForm := func() ServerConfig {
		mode := "global"
		if strings.Contains(routingSelect.Selected, "Bypass") {
			mode = "bypass_cn"
		}
		if strings.Contains(routingSelect.Selected, "Direct") {
			mode = "none"
		}
		return ServerConfig{
			Name: nameEntry.Text, ServerAddr: addrEntry.Text, ListenAddr: listenEntry.Text,
			Token: tokenEntry.Text, ServerIP: ipEntry.Text, DNSServer: dnsEntry.Text,
			ECHDomain: echEntry.Text, RoutingMode: mode,
		}
	}

	currIdx := -1
	for i, s := range config.Servers {
		if s.ID == config.CurrentServerID {
			currIdx = i
			break
		}
	}
	if currIdx >= 0 {
		fillForm(config.Servers[currIdx])
		serverCombo.SetSelectedIndex(currIdx)
	}

	serverCombo.OnChanged = func(s string) {
		idx := serverCombo.SelectedIndex()
		if idx >= 0 && idx < len(config.Servers) {
			fillForm(config.Servers[idx])
			config.CurrentServerID = config.Servers[idx].ID
		}
	}

	saveBtn := widget.NewButtonWithIcon("Save", theme.DocumentSaveIcon(), func() {
		idx := serverCombo.SelectedIndex()
		if idx >= 0 {
			form := getForm()
			form.ID = config.Servers[idx].ID
			config.Servers[idx] = form
			saveConfig(config)
			refreshServerCombo(serverCombo, config)
			serverCombo.SetSelectedIndex(idx)
			dialog.ShowInformation("Success", "Configuration Saved", w)
		}
	})

	newBtn := widget.NewButtonWithIcon("New", theme.ContentAddIcon(), func() {
		newS := ServerConfig{ID: fmt.Sprintf("%d", time.Now().Unix()), Name: "New Profile", ListenAddr: "127.0.0.1:30000", RoutingMode: "bypass_cn"}
		config.Servers = append(config.Servers, newS)
		config.CurrentServerID = newS.ID
		refreshServerCombo(serverCombo, config)
		serverCombo.SetSelectedIndex(len(config.Servers) - 1)
	})

	// --- Control Buttons ---
	
	pingBtn := widget.NewButtonWithIcon("Ping", theme.ViewRefreshIcon(), func() {
		cfg := getForm()
		if cfg.ServerAddr == "" { return }
		go func() {
			latencyShow.Set("Pinging...")
			ms, err := measureLatency(cfg)
			if err != nil {
				latencyShow.Set("Error")
				guiLog("Ping Failed: %v", err)
			} else {
				latencyShow.Set(fmt.Sprintf("Latency: %d ms", ms))
				guiLog("Ping Result: %d ms", ms)
			}
		}()
	})

	logEntry := widget.NewMultiLineEntry()
	logEntry.TextStyle = fyne.TextStyle{Monospace: true}
	logEntry.Bind(logType)

	startBtn := widget.NewButtonWithIcon("Start Proxy", theme.MediaPlayIcon(), nil)
	stopBtn := widget.NewButtonWithIcon("Stop", theme.MediaStopIcon(), nil)
	proxyBtn := widget.NewButton("Set System Proxy", nil)

	startBtn.OnTapped = func() {
		activeConfig = getForm()
		if activeConfig.ServerAddr == "" {
			dialog.ShowError(errors.New("Server address required"), w)
			return
		}
		if activeConfig.ECHDomain == "" { activeConfig.ECHDomain = "cloudflare-ech.com" }
		if activeConfig.DNSServer == "" { activeConfig.DNSServer = "dns.alidns.com/dns-query" }

		logType.Set("")
		guiLog("Initializing...")
		if err := startProxyCore(); err != nil {
			guiLog("Start Failed: " + err.Error())
			return
		}
		saveConfig(config)
		proxyRunning.Set(true)
		statusLabel.Set("Status: Running")
	}

	stopBtn.OnTapped = func() {
		if systemProxyEnabled {
			setSystemProxy(false, activeConfig.ListenAddr, activeConfig.RoutingMode)
			systemProxyEnabled = false
			proxyBtn.SetText("Set System Proxy")
		}
		stopProxyCore()
		proxyRunning.Set(false)
		statusLabel.Set("Status: Stopped")
		guiLog("Proxy Stopped")
	}

	proxyBtn.OnTapped = func() {
		systemProxyEnabled = !systemProxyEnabled
		if systemProxyEnabled {
			guiLog("Setting System Proxy...")
			if setSystemProxy(true, activeConfig.ListenAddr, activeConfig.RoutingMode) {
				proxyBtn.SetText("Unset System Proxy")
				guiLog("System Proxy Enabled")
			} else {
				systemProxyEnabled = false
				guiLog("System Proxy Failed")
			}
		} else {
			setSystemProxy(false, activeConfig.ListenAddr, activeConfig.RoutingMode)
			proxyBtn.SetText("Set System Proxy")
			guiLog("System Proxy Disabled")
		}
	}

	proxyRunning.AddListener(binding.NewDataListener(func() {
		isRunning, _ := proxyRunning.Get()
		if isRunning {
			startBtn.Disable()
			serverCombo.Disable()
			stopBtn.Enable()
			proxyBtn.Enable()
		} else {
			startBtn.Enable()
			serverCombo.Enable()
			stopBtn.Disable()
			proxyBtn.Disable()
		}
	}))
	proxyRunning.Set(false)

	// --- Layout ---
	cardServer := widget.NewCard("Profile", "", container.NewBorder(nil, nil, nil, container.NewHBox(newBtn, saveBtn), serverCombo))
	
	form := container.NewVBox(
		widget.NewForm(
			widget.NewFormItem("Name", nameEntry),
			widget.NewFormItem("Server Addr", addrEntry),
			widget.NewFormItem("Local Listen", listenEntry),
			widget.NewFormItem("Auth Token", tokenEntry),
			widget.NewFormItem("Preferred IP", ipEntry),
		),
		widget.NewForm(
			widget.NewFormItem("DoH Server", dnsEntry),
			widget.NewFormItem("ECH Domain", echEntry),
			widget.NewFormItem("Routing", routingSelect),
		),
	)
	cardSettings := widget.NewCard("Settings", "", form)

	// Status Bar
	statBox := container.NewHBox(
		widget.NewLabelWithData(statusLabel),
		layout.NewSpacer(),
		widget.NewLabelWithData(speedDownload),
		widget.NewLabel("|"),
		widget.NewLabelWithData(speedUpload),
		layout.NewSpacer(),
		widget.NewLabelWithData(latencyShow),
		pingBtn,
	)
	cardStats := widget.NewCard("Monitor", "", statBox)

	ctrlBox := container.NewHBox(startBtn, stopBtn, layout.NewSpacer(), proxyBtn)
	logContainer := container.NewGridWrap(fyne.NewSize(800, 180), logEntry)
	cardControl := widget.NewCard("Control", "", container.NewVBox(ctrlBox, logContainer))

	content := container.NewVBox(cardServer, cardSettings, cardStats, cardControl)
	w.SetContent(content)

	// --- System Tray & Close Logic ---
	if desk, ok := myApp.(desktop.App); ok {
		menu := fyne.NewMenu("ECH Client",
			fyne.NewMenuItem("Show", func() { w.Show() }),
			fyne.NewMenuItem("Quit", func() {
				if systemProxyEnabled {
					setSystemProxy(false, activeConfig.ListenAddr, activeConfig.RoutingMode)
				}
				myApp.Quit()
			}),
		)
		desk.SetSystemTrayMenu(menu)
	}

	w.SetCloseIntercept(func() { w.Hide() })
	w.ShowAndRun()
}

// ======================== Monitor & Tools ========================

func startSpeedMonitor() {
	var lastUp, lastDown uint64
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		currUp := atomic.LoadUint64(&totalUp)
		currDown := atomic.LoadUint64(&totalDown)

		upRate := currUp - lastUp
		downRate := currDown - lastDown

		lastUp = currUp
		lastDown = currDown

		speedUpload.Set(fmt.Sprintf("Up: %s/s", formatBytes(upRate)))
		speedDownload.Set(fmt.Sprintf("Down: %s/s", formatBytes(downRate)))
	}
}

func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func measureLatency(cfg ServerConfig) (int64, error) {
	host, port, _ := net.SplitHostPort(cfg.ServerAddr)
	if host == "" { host = cfg.ServerAddr; port = "443" }
	
	target := host + ":" + port
	if cfg.ServerIP != "" {
		target = cfg.ServerIP + ":" + port
	}

	start := time.Now()
	conn, err := net.DialTimeout("tcp", target, 3*time.Second)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	return time.Since(start).Milliseconds(), nil
}

// ======================== Core Helpers ========================

func refreshServerCombo(combo *widget.Select, config AppConfig) {
	names := []string{}
	for _, s := range config.Servers {
		names = append(names, s.Name)
	}
	combo.Options = names
	combo.Refresh()
}

var logBuffer bytes.Buffer
var logMu sync.Mutex

func guiLog(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	logMu.Lock()
	defer logMu.Unlock()
	if logBuffer.Len() > 20000 {
		logBuffer.Reset()
		logBuffer.WriteString("... (Log Truncated) ...\n")
	}
	ts := time.Now().Format("15:04:05")
	line := fmt.Sprintf("[%s] %s\n", ts, msg)
	logBuffer.WriteString(line)
	logType.Set(logBuffer.String())
}

// ======================== Networking Core ========================

func startProxyCore() error {
	guiLog("Fetching ECH Config (%s)...", activeConfig.ECHDomain)
	if err := prepareECH(activeConfig.ECHDomain, activeConfig.DNSServer); err != nil {
		return err
	}

	if activeConfig.RoutingMode == "bypass_cn" {
		go loadChinaIPList()
	}

	l, err := net.Listen("tcp", activeConfig.ListenAddr)
	if err != nil {
		return err
	}
	proxyListener = l
	proxyContext, proxyCancel = context.WithCancel(context.Background())

	go func() {
		guiLog("Proxy Started: %s", activeConfig.ListenAddr)
		for {
			conn, err := l.Accept()
			if err != nil {
				select {
				case <-proxyContext.Done():
					return
				default:
					time.Sleep(time.Second)
					continue
				}
			}
			go handleConnection(conn)
		}
	}()
	return nil
}

func stopProxyCore() {
	if proxyCancel != nil {
		proxyCancel()
	}
	if proxyListener != nil {
		proxyListener.Close()
	}
}

// Wraps net.Conn to count bytes
type CountConn struct {
	net.Conn
}

func (c *CountConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if n > 0 {
		atomic.AddUint64(&totalDown, uint64(n))
	}
	return
}

func (c *CountConn) Write(b []byte) (n int, err error) {
	n, err = c.Conn.Write(b)
	if n > 0 {
		atomic.AddUint64(&totalUp, uint64(n))
	}
	return
}

func handleConnection(conn net.Conn) {
	// Wrap connection for statistics
	conn = &CountConn{Conn: conn}
	
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	buf := make([]byte, 1)
	n, err := conn.Read(buf)
	if err != nil || n == 0 { return }
	firstByte := buf[0]

	switch firstByte {
	case 0x05:
		handleSOCKS5(conn, firstByte)
	case 'C', 'G', 'P', 'H', 'D', 'O', 'T':
		handleHTTP(conn, firstByte)
	}
}

func handleSOCKS5(conn net.Conn, firstByte byte) {
	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil { return }
	nmethods := buf[0]
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(conn, methods); err != nil { return }
	conn.Write([]byte{0x05, 0x00})

	buf = make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil { return }
	cmd := buf[1]
	atyp := buf[3]

	var host string
	switch atyp {
	case 0x01:
		ip := make([]byte, 4)
		io.ReadFull(conn, ip)
		host = net.IP(ip).String()
	case 0x03:
		lb := make([]byte, 1)
		io.ReadFull(conn, lb)
		dom := make([]byte, lb[0])
		io.ReadFull(conn, dom)
		host = string(dom)
	case 0x04:
		ip := make([]byte, 16)
		io.ReadFull(conn, ip)
		host = net.IP(ip).String()
	}

	pBuf := make([]byte, 2)
	io.ReadFull(conn, pBuf)
	port := binary.BigEndian.Uint16(pBuf)
	target := fmt.Sprintf("%s:%d", host, port)

	if cmd == 0x01 {
		handleTunnel(conn, target, 1, "")
	} else {
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	}
}

func handleHTTP(conn net.Conn, firstByte byte) {
	reader := bufio.NewReader(io.MultiReader(bytes.NewReader([]byte{firstByte}), conn))
	reqLine, err := reader.ReadString('\n')
	if err != nil { return }

	parts := strings.Fields(reqLine)
	if len(parts) < 3 { return }
	method, urlStr, ver := parts[0], parts[1], parts[2]

	var headers []string
	var hostHeader string
	for {
		line, err := reader.ReadString('\n')
		if err != nil || line == "\r\n" { break }
		headers = append(headers, line)
		if strings.HasPrefix(strings.ToLower(line), "host:") {
			hostHeader = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		}
	}

	if method == "CONNECT" {
		handleTunnel(conn, urlStr, 2, "")
	} else {
		target := hostHeader
		if target == "" {
			u, _ := url.Parse(urlStr)
			target = u.Host
		}
		if !strings.Contains(target, ":") { target += ":80" }

		var buf bytes.Buffer
		path := urlStr
		if strings.HasPrefix(urlStr, "http://") {
			if u, err := url.Parse(urlStr); err == nil {
				path = u.Path
				if u.RawQuery != "" { path += "?" + u.RawQuery }
				if path == "" { path = "/" }
			}
		}
		fmt.Fprintf(&buf, "%s %s %s\r\n", method, path, ver)
		for _, h := range headers {
			if !strings.HasPrefix(strings.ToLower(h), "proxy-") {
				buf.WriteString(h)
			}
		}
		buf.WriteString("\r\n")

		if n := reader.Buffered(); n > 0 {
			b := make([]byte, n)
			reader.Read(b)
			buf.Write(b)
		}
		handleTunnel(conn, target, 3, buf.String())
	}
}

func handleTunnel(conn net.Conn, target string, mode int, firstFrame string) {
	host, _, _ := net.SplitHostPort(target)
	if shouldBypass(host) {
		handleDirect(conn, target, mode, firstFrame)
		return
	}

	ws, err := dialWebSocketWithECH(2)
	if err != nil {
		sendError(conn, mode)
		return
	}
	defer ws.Close()

	conn.SetDeadline(time.Time{})

	payload := fmt.Sprintf("CONNECT:%s|%s", target, firstFrame)
	ws.WriteMessage(websocket.TextMessage, []byte(payload))

	_, msg, err := ws.ReadMessage()
	if err != nil || string(msg) != "CONNECTED" {
		sendError(conn, mode)
		return
	}

	if mode == 1 {
		conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	} else if mode == 2 {
		conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	}

	var mu sync.Mutex
	done := make(chan bool, 2)

	go func() {
		tk := time.NewTicker(10 * time.Second)
		defer tk.Stop()
		for {
			select {
			case <-tk.C:
				mu.Lock()
				ws.WriteMessage(websocket.PingMessage, nil)
				mu.Unlock()
			case <-done:
				return
			}
		}
	}()

	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := conn.Read(buf)
			if err != nil { break }
			mu.Lock()
			ws.WriteMessage(websocket.BinaryMessage, buf[:n])
			mu.Unlock()
		}
		done <- true
	}()

	go func() {
		for {
			mt, data, err := ws.ReadMessage()
			if err != nil { break }
			if mt == websocket.TextMessage && string(data) == "CLOSE" { break }
			if mt == websocket.BinaryMessage || mt == websocket.TextMessage {
				if _, err := conn.Write(data); err != nil { break }
			}
		}
		done <- true
	}()

	<-done
}

func handleDirect(conn net.Conn, target string, mode int, firstFrame string) {
	remote, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		sendError(conn, mode)
		return
	}
	defer remote.Close()

	if mode == 1 {
		conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	} else if mode == 2 {
		conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	}

	if firstFrame != "" {
		remote.Write([]byte(firstFrame))
	}

	go io.Copy(remote, conn)
	io.Copy(conn, remote)
}

func sendError(conn net.Conn, mode int) {
	if mode == 1 {
		conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	} else {
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
	}
}

// ======================== ECH Logic ========================

func prepareECH(domain, dns string) error {
	dohURL := dns
	if !strings.HasPrefix(dohURL, "http") { dohURL = "https://" + dohURL }
	
	u, _ := url.Parse(dohURL)
	dnsQuery := make([]byte, 0, 512)
	dnsQuery = append(dnsQuery, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0)
	for _, l := range strings.Split(domain, ".") {
		dnsQuery = append(dnsQuery, byte(len(l)))
		dnsQuery = append(dnsQuery, []byte(l)...)
	}
	dnsQuery = append(dnsQuery, 0)
	dnsQuery = append(dnsQuery, 0, 65, 0, 1)

	b64 := base64.RawURLEncoding.EncodeToString(dnsQuery)
	q := u.Query()
	q.Set("dns", b64)
	u.RawQuery = q.Encode()

	req, _ := http.NewRequest("GET", u.String(), nil)
	req.Header.Set("Accept", "application/dns-message")
	
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil { return err }
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if len(body) < 12 { return errors.New("DNS response too short") }
	
	idx := 12
	for idx < len(body) && body[idx] != 0 { idx += int(body[idx]) + 1 }
	idx += 5
	
	ancount := binary.BigEndian.Uint16(body[6:8])
	for i := 0; i < int(ancount); i++ {
		if idx >= len(body) { break }
		if body[idx]&0xC0 == 0xC0 { idx += 2 } else {
			for idx < len(body) && body[idx] != 0 { idx += int(body[idx]) + 1 }
			idx++
		}
		if idx+8 > len(body) { break }
		rtype := binary.BigEndian.Uint16(body[idx:idx+2])
		idx += 8
		rdlen := binary.BigEndian.Uint16(body[idx:idx+2])
		idx += 2
		
		if rtype == 65 {
			rdata := body[idx : idx+int(rdlen)]
			p := 2
			if p < len(rdata) && rdata[p] == 0 { p++ } else {
				for p < len(rdata) && rdata[p] != 0 { p += int(rdata[p]) + 1 }
				p++
			}
			for p+4 <= len(rdata) {
				key := binary.BigEndian.Uint16(rdata[p:p+2])
				valLen := binary.BigEndian.Uint16(rdata[p+2:p+4])
				p += 4
				if key == 5 {
					echListMu.Lock()
					echList = rdata[p : p+int(valLen)]
					echListMu.Unlock()
					return nil
				}
				p += int(valLen)
			}
		}
		idx += int(rdlen)
	}
	return errors.New("ECH Config not found")
}

func dialWebSocketWithECH(retries int) (*websocket.Conn, error) {
	for i := 0; i < retries; i++ {
		host, port, _ := net.SplitHostPort(activeConfig.ServerAddr)
		if host == "" { host = activeConfig.ServerAddr; port = "443" }

		echListMu.RLock()
		curECH := echList
		echListMu.RUnlock()

		if len(curECH) == 0 {
			prepareECH(activeConfig.ECHDomain, activeConfig.DNSServer)
		}

		roots, _ := x509.SystemCertPool()
		tlsCfg := &tls.Config{
			MinVersion: tls.VersionTLS13,
			ServerName: host,
			RootCAs: roots,
		}
		
		v := reflect.ValueOf(tlsCfg).Elem()
		f := v.FieldByName("EncryptedClientHelloConfigList")
		if f.IsValid() { f.Set(reflect.ValueOf(curECH)) }
		f2 := v.FieldByName("EncryptedClientHelloRejectionVerify")
		if f2.IsValid() {
			fn := func(cs tls.ConnectionState) error { return errors.New("ECH Rejected") }
			f2.Set(reflect.ValueOf(fn))
		}

		dialer := websocket.Dialer{
			TLSClientConfig: tlsCfg,
			HandshakeTimeout: 10 * time.Second,
		}
		if activeConfig.Token != "" {
			dialer.Subprotocols = []string{activeConfig.Token}
		}
		
		if activeConfig.ServerIP != "" {
			dialer.NetDial = func(network, addr string) (net.Conn, error) {
				return net.Dial(network, activeConfig.ServerIP+":"+port)
			}
		}

		url := fmt.Sprintf("wss://%s:%s/", host, port)
		ws, _, err := dialer.Dial(url, nil)
		if err == nil { return ws, nil }
		
		time.Sleep(500 * time.Millisecond)
	}
	return nil, errors.New("WS Dial Failed")
}

// ======================== Helpers ========================

func shouldBypass(host string) bool {
	if activeConfig.RoutingMode == "none" { return true }
	if activeConfig.RoutingMode == "global" { return false }
	ip := net.ParseIP(host)
	if ip == nil {
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 { return false }
		ip = ips[0]
	}
	return isChinaIP(ip)
}

func isChinaIP(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil { return false }
	val := binary.BigEndian.Uint32(ip4)
	chinaIPRangesMu.RLock()
	defer chinaIPRangesMu.RUnlock()
	l, r := 0, len(chinaIPRanges)
	for l < r {
		m := (l + r) / 2
		rg := chinaIPRanges[m]
		if val < rg.start {
			r = m
		} else if val > rg.end {
			l = m + 1
		} else {
			return true
		}
	}
	return false
}

func loadChinaIPList() {
	path := "chn_ip.txt"
	if _, err := os.Stat(path); os.IsNotExist(err) {
		guiLog("Downloading China IP List...")
		resp, err := http.Get("https://raw.githubusercontent.com/mayaxcn/china-ip-list/refs/heads/master/chn_ip.txt")
		if err == nil {
			defer resp.Body.Close()
			content, _ := io.ReadAll(resp.Body)
			os.WriteFile(path, content, 0644)
		}
	}

	f, err := os.Open(path)
	if err != nil { return }
	defer f.Close()

	var list []ipRange
	scan := bufio.NewScanner(f)
	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		if line == "" || line[0] == '#' { continue }
		p := strings.Fields(line)
		if len(p) < 2 { continue }
		s, e := net.ParseIP(p[0]), net.ParseIP(p[1])
		if s != nil && e != nil {
			list = append(list, ipRange{
				binary.BigEndian.Uint32(s.To4()),
				binary.BigEndian.Uint32(e.To4()),
			})
		}
	}
	chinaIPRangesMu.Lock()
	chinaIPRanges = list
	chinaIPRangesMu.Unlock()
	guiLog("Loaded %d CN IP Rules", len(list))
}

func loadConfig() AppConfig {
	var cfg AppConfig
	f, err := os.Open("config.json")
	if err == nil {
		defer f.Close()
		json.NewDecoder(f).Decode(&cfg)
	}
	return cfg
}

func saveConfig(cfg AppConfig) {
	f, _ := os.Create("config.json")
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	enc.Encode(cfg)
}

func setSystemProxy(enable bool, listen, mode string) bool {
	if mode == "none" { return true }
	_, port, _ := net.SplitHostPort(listen)
	if port == "" { return false }

	if runtime.GOOS == "windows" {
		if enable {
			exec.Command("reg", "add", `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "1", "/f").Run()
			exec.Command("reg", "add", `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`, "/v", "ProxyServer", "/t", "REG_SZ", "/d", "127.0.0.1:"+port, "/f").Run()
			exec.Command("reg", "add", `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`, "/v", "ProxyOverride", "/t", "REG_SZ", "/d", "localhost;127.*;10.*;172.*;192.168.*;<local>", "/f").Run()
		} else {
			exec.Command("reg", "add", `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "0", "/f").Run()
		}
		return true
	} else if runtime.GOOS == "darwin" {
		svc := "Wi-Fi"
		if enable {
			exec.Command("networksetup", "-setsocksfirewallproxy", svc, "127.0.0.1", port).Run()
			exec.Command("networksetup", "-setsocksfirewallproxystate", svc, "on").Run()
		} else {
			exec.Command("networksetup", "-setsocksfirewallproxystate", svc, "off").Run()
		}
		return true
	}
	return false
}
