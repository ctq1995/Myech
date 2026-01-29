package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
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

	currentConfig ServerConfig
	proxyListener net.Listener
	proxyContext  context.Context
	proxyCancel   context.CancelFunc

	echListMu       sync.RWMutex
	echList         []byte
	chinaIPRangesMu sync.RWMutex
	chinaIPRanges   []ipRange

	systemProxyEnabled bool
)

// ======================== GUI Main ========================

func main() {
	// Fix blurry text on Windows (Best effort)
	os.Setenv("FYNE_SCALE", "1")

	myApp := app.NewWithID("com.echworkers.client")
	// Use default theme which supports English perfectly
	myApp.Settings().SetTheme(theme.LightTheme())

	w := myApp.NewWindow("ECH Client")
	w.Resize(fyne.NewSize(850, 700))
	w.CenterOnScreen()

	config := loadConfig()
	if len(config.Servers) == 0 {
		config.Servers = append(config.Servers, ServerConfig{
			ID: "default", Name: "Default Profile", ServerAddr: "example.workers.dev:443",
			ListenAddr: "127.0.0.1:30000", ECHDomain: "cloudflare-ech.com", RoutingMode: "bypass_cn",
		})
		config.CurrentServerID = "default"
	}

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

	logEntry := widget.NewMultiLineEntry()
	logEntry.TextStyle = fyne.TextStyle{Monospace: true}
	logEntry.Bind(logType)

	startBtn := widget.NewButtonWithIcon("Start Proxy", theme.MediaPlayIcon(), nil)
	stopBtn := widget.NewButtonWithIcon("Stop", theme.MediaStopIcon(), nil)
	proxyBtn := widget.NewButton("Set System Proxy", nil)

	startBtn.OnTapped = func() {
		currentConfig = getForm()
		if currentConfig.ServerAddr == "" {
			dialog.ShowError(errors.New("Server address required"), w)
			return
		}
		logType.Set("")
		guiLog("Starting...")
		if err := startProxyCore(); err != nil {
			guiLog("Start Failed: " + err.Error())
			return
		}
		saveConfig(config)
		proxyRunning.Set(true)
	}

	stopBtn.OnTapped = func() {
		if systemProxyEnabled {
			setSystemProxy(false, currentConfig.ListenAddr, currentConfig.RoutingMode)
			systemProxyEnabled = false
			proxyBtn.SetText("Set System Proxy")
		}
		stopProxyCore()
		proxyRunning.Set(false)
		guiLog("Proxy Stopped")
	}

	proxyBtn.OnTapped = func() {
		systemProxyEnabled = !systemProxyEnabled
		if systemProxyEnabled {
			guiLog("Setting System Proxy...")
			if setSystemProxy(true, currentConfig.ListenAddr, currentConfig.RoutingMode) {
				proxyBtn.SetText("Unset System Proxy")
				guiLog("System Proxy Enabled")
			} else {
				systemProxyEnabled = false
				guiLog("System Proxy Failed")
			}
		} else {
			setSystemProxy(false, currentConfig.ListenAddr, currentConfig.RoutingMode)
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
	ctrlBox := container.NewHBox(startBtn, stopBtn, layout.NewSpacer(), proxyBtn)
	logContainer := container.NewGridWrap(fyne.NewSize(800, 200), logEntry)
	cardControl := widget.NewCard("Control", "", container.NewVBox(ctrlBox, logContainer))

	content := container.NewVBox(cardServer, cardSettings, cardControl)
	w.SetContent(content)

	if desk, ok := myApp.(desktop.App); ok {
		menu := fyne.NewMenu("ECH Client",
			fyne.NewMenuItem("Show", func() { w.Show() }),
			fyne.NewMenuItem("Quit", func() {
				if systemProxyEnabled {
					setSystemProxy(false, currentConfig.ListenAddr, currentConfig.RoutingMode)
				}
				myApp.Quit()
			}),
		)
		desk.SetSystemTrayMenu(menu)
	}

	w.SetCloseIntercept(func() { w.Hide() })
	w.ShowAndRun()
}

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
	if logBuffer.Len() > 10000 {
		logBuffer.Reset()
		logBuffer.WriteString("... (Log Truncated) ...\n")
	}
	ts := time.Now().Format("15:04:05")
	line := fmt.Sprintf("[%s] %s\n", ts, msg)
	logBuffer.WriteString(line)
	logType.Set(logBuffer.String())
}

// ======================== Core Logic ========================

func startProxyCore() error {
	if currentConfig.ECHDomain == "" {
		currentConfig.ECHDomain = "cloudflare-ech.com"
	}
	if currentConfig.DNSServer == "" {
		currentConfig.DNSServer = "dns.alidns.com/dns-query"
	}

	guiLog("Fetching ECH Config (%s)...", currentConfig.ECHDomain)
	if err := prepareECH(currentConfig.ECHDomain, currentConfig.DNSServer); err != nil {
		return err
	}

	if currentConfig.RoutingMode == "bypass_cn" {
		go loadChinaIPList()
	}

	l, err := net.Listen("tcp", currentConfig.ListenAddr)
	if err != nil {
		return err
	}
	proxyListener = l
	proxyContext, proxyCancel = context.WithCancel(context.Background())

	go func() {
		guiLog("Proxy Started: %s", currentConfig.ListenAddr)
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

type ipRange struct{ start, end uint32 }

func loadChinaIPList() {
	url := "https://raw.githubusercontent.com/mayaxcn/china-ip-list/refs/heads/master/chn_ip.txt"
	resp, err := http.Get(url)
	if err != nil {
		guiLog("Failed to download IP list: %v", err)
		return
	}
	defer resp.Body.Close()

	scan := bufio.NewScanner(resp.Body)
	var ranges []ipRange
	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			s, e := net.ParseIP(parts[0]), net.ParseIP(parts[1])
			if s != nil && e != nil {
				ranges = append(ranges, ipRange{ipToUint32(s), ipToUint32(e)})
			}
		}
	}
	chinaIPRangesMu.Lock()
	chinaIPRanges = ranges
	chinaIPRangesMu.Unlock()
	guiLog("Loaded %d China IP rules", len(ranges))
}

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip)
}

func isChinaIP(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	v4 := ipToUint32(ip)
	if v4 > 0 {
		chinaIPRangesMu.RLock()
		defer chinaIPRangesMu.RUnlock()
		l, r := 0, len(chinaIPRanges)
		for l < r {
			m := (l + r) / 2
			rg := chinaIPRanges[m]
			if v4 < rg.start {
				r = m
			} else if v4 > rg.end {
				l = m + 1
			} else {
				return true
			}
		}
	}
	return false
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}
	firstByte := buf[0]
	multiReader := io.MultiReader(bytes.NewReader(buf), conn)

	if firstByte == 0x05 {
		handleSOCKS5(conn, multiReader)
	} else {
		handleHTTP(conn, multiReader)
	}
}

func handleSOCKS5(conn net.Conn, reader io.Reader) {
	p1 := make([]byte, 2)
	io.ReadFull(reader, p1)
	nMethods := int(p1[1])
	io.ReadFull(reader, make([]byte, nMethods))
	conn.Write([]byte{0x05, 0x00})

	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return
	}
	cmd := head[1]
	atyp := head[3]
	var dest string

	switch atyp {
	case 1:
		ip := make([]byte, 4)
		io.ReadFull(conn, ip)
		dest = net.IP(ip).String()
	case 3:
		lenB := make([]byte, 1)
		io.ReadFull(conn, lenB)
		dom := make([]byte, int(lenB[0]))
		io.ReadFull(conn, dom)
		dest = string(dom)
	case 4:
		ip := make([]byte, 16)
		io.ReadFull(conn, ip)
		dest = net.IP(ip).String()
	}

	portB := make([]byte, 2)
	io.ReadFull(conn, portB)
	port := binary.BigEndian.Uint16(portB)
	target := fmt.Sprintf("%s:%d", dest, port)

	if cmd == 1 {
		doProxy(conn, target, "SOCKS5", "")
	}
}

func handleHTTP(conn net.Conn, reader io.Reader) {
	bufReader := bufio.NewReader(reader)
	reqLine, err := bufReader.ReadString('\n')
	if err != nil {
		return
	}
	parts := strings.Fields(reqLine)
	if len(parts) < 2 {
		return
	}
	method, urlStr := parts[0], parts[1]

	if method == "CONNECT" {
		doProxy(conn, urlStr, "HTTP_CONNECT", "")
	} else {
		target := urlStr
		if strings.HasPrefix(target, "http") {
			u, _ := url.Parse(urlStr)
			target = u.Host
		}
		if !strings.Contains(target, ":") {
			target += ":80"
		}
		extraL := bufReader.Buffered()
		p, _ := bufReader.Peek(extraL)
		fullReq := reqLine + string(p)
		doProxy(conn, target, "HTTP_PROXY", fullReq)
	}
}

func doProxy(conn net.Conn, target string, mode string, firstFrame string) {
	bypass := false
	host, _, _ := net.SplitHostPort(target)
	if currentConfig.RoutingMode == "none" {
		bypass = true
	}
	if currentConfig.RoutingMode == "bypass_cn" && isChinaIP(host) {
		bypass = true
	}

	if bypass {
		remote, err := net.DialTimeout("tcp", target, 5*time.Second)
		if err != nil {
			return
		}
		defer remote.Close()
		if mode == "SOCKS5" {
			conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		}
		if mode == "HTTP_CONNECT" {
			conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		}
		if firstFrame != "" {
			remote.Write([]byte(firstFrame))
		}
		go io.Copy(remote, conn)
		io.Copy(conn, remote)
		return
	}

	ws, err := dialWS(currentConfig.ServerAddr, currentConfig.ServerIP, currentConfig.Token)
	if err != nil {
		return
	}
	defer ws.Close()

	if mode == "SOCKS5" {
		conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	}
	if mode == "HTTP_CONNECT" {
		conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	}

	payload := fmt.Sprintf("CONNECT:%s|%s", target, firstFrame)
	ws.WriteMessage(websocket.TextMessage, []byte(payload))

	_, msg, err := ws.ReadMessage()
	if err != nil || string(msg) != "CONNECTED" {
		return
	}

	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				ws.WriteMessage(websocket.TextMessage, []byte("CLOSE"))
				break
			}
			ws.WriteMessage(websocket.BinaryMessage, buf[:n])
		}
	}()

	for {
		mt, data, err := ws.ReadMessage()
		if err != nil {
			break
		}
		if mt == websocket.TextMessage && string(data) == "CLOSE" {
			break
		}
		conn.Write(data)
	}
}

// ======================== ECH Logic ========================

// 1. queryHTTPSRecord (DoH)
func prepareECH(domain, dns string) error {
	dohURL := dns
	if !strings.HasPrefix(dohURL, "http") {
		dohURL = "https://" + dohURL
	}
	u, _ := url.Parse(dohURL)
	
	// DNS Query (Type 65 - HTTPS)
	// Header: ID=0, Flags=RD, QDCOUNT=1
	q := []byte{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(domain, ".") {
		q = append(q, byte(len(label)))
		q = append(q, []byte(label)...)
	}
	q = append(q, 0)             // Root
	q = append(q, 0, 65, 0, 1)   // Type 65, Class 1

	b64 := base64.RawURLEncoding.EncodeToString(q)
	query := u.Query()
	query.Set("dns", b64)
	u.RawQuery = query.Encode()

	req, _ := http.NewRequest("GET", u.String(), nil)
	req.Header.Set("Accept", "application/dns-message")
	
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil { return err }
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	// Parse DoH Response
	if len(body) < 12 { return errors.New("DNS response too short") }
	idx := 12
	// Skip Question
	for idx < len(body) && body[idx] != 0 { idx += int(body[idx]) + 1 }
	idx += 5 // 0x00 + Type(2) + Class(2)
	
	// Answers
	ancount := binary.BigEndian.Uint16(body[6:8])
	for i := 0; i < int(ancount); i++ {
		if idx >= len(body) { break }
		// Name
		if body[idx]&0xC0 == 0xC0 { idx += 2 } else {
			for idx < len(body) && body[idx] != 0 { idx += int(body[idx]) + 1 }
			idx++
		}
		// Type, Class, TTL, RDLENGTH
		if idx+10 > len(body) { break }
		rtype := binary.BigEndian.Uint16(body[idx : idx+2])
		rdlen := binary.BigEndian.Uint16(body[idx+8 : idx+10])
		idx += 10
		rdata := body[idx : idx+int(rdlen)]
		idx += int(rdlen)

		if rtype == 65 { // HTTPS
			// Parse HTTPS RData
			p := 0
			// Priority (2)
			p += 2
			// Target Name
			if p < len(rdata) && rdata[p] == 0 { p++ } else {
				for p < len(rdata) && rdata[p] != 0 { p += int(rdata[p]) + 1 }
				p++
			}
			// Params (Key-Value pairs)
			for p+4 <= len(rdata) {
				key := binary.BigEndian.Uint16(rdata[p : p+2])
				valLen := binary.BigEndian.Uint16(rdata[p+2 : p+4])
				p += 4
				if key == 5 { // ECH Config
					echListMu.Lock()
					echList = rdata[p : p+int(valLen)]
					echListMu.Unlock()
					return nil
				}
				p += int(valLen)
			}
		}
	}
	
	return errors.New("ECH Config not found")
}

func dialWS(addr, ip, token string) (*websocket.Conn, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: strings.Split(addr, ":")[0],
	}

	echListMu.RLock()
	myEch := echList
	echListMu.RUnlock()

	if len(myEch) > 0 {
		setECHConfig(tlsConfig, myEch)
	}

	dialer := websocket.Dialer{TLSClientConfig: tlsConfig, HandshakeTimeout: 5 * time.Second}
	if ip != "" {
		dialer.NetDial = func(network, address string) (net.Conn, error) {
			_, port, _ := net.SplitHostPort(address)
			return net.Dial(network, ip+":"+port)
		}
	}
	if token != "" {
		dialer.Subprotocols = []string{token}
	}

	url := fmt.Sprintf("wss://%s/", addr)
	c, _, err := dialer.Dial(url, nil)
	return c, err
}

func setECHConfig(config *tls.Config, echList []byte) {
	v := reflect.ValueOf(config).Elem()
	f := v.FieldByName("EncryptedClientHelloConfigList")
	if f.IsValid() && f.CanSet() {
		f.Set(reflect.ValueOf(echList))
	}
	f2 := v.FieldByName("EncryptedClientHelloRejectionVerify")
	if f2.IsValid() && f2.CanSet() {
		// Mock function
		fn := func(cs tls.ConnectionState) error { return errors.New("rejected") }
		f2.Set(reflect.ValueOf(fn))
	}
}

// ======================== Config & System ========================

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
	if mode == "none" {
		return true
	}
	_, port, _ := net.SplitHostPort(listen)
	if port == "" {
		return false
	}

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
		svc := "Wi-Fi" // Simplified
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
