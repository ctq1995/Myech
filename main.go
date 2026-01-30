package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"image/color"
	"io"
	"math/big"
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
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/gorilla/websocket"
)

// ======================== 资源与主题 ========================

//go:embed font.ttf
var embedFontData []byte

type CompactTheme struct{}
var _ fyne.Theme = (*CompactTheme)(nil)

func (m CompactTheme) Font(s fyne.TextStyle) fyne.Resource {
	return &fyne.StaticResource{StaticName: "font.ttf", StaticContent: embedFontData}
}
func (m CompactTheme) Color(n fyne.ThemeColorName, v fyne.ThemeVariant) color.Color {
	if n == theme.ColorNamePrimary { return color.RGBA{R: 0, G: 110, B: 220, A: 255} }
	if n == theme.ColorNameBackground { return color.RGBA{R: 248, G: 248, B: 250, A: 255} }
	return theme.DefaultTheme().Color(n, theme.VariantLight)
}
func (m CompactTheme) Icon(n fyne.ThemeIconName) fyne.Resource { return theme.DefaultTheme().Icon(n) }
func (m CompactTheme) Size(n fyne.ThemeSizeName) float32 {
	if n == theme.SizeNamePadding { return 2 } // 极小内边距
	if n == theme.SizeNameText { return 12 }   // 小字体
	return theme.DefaultTheme().Size(n)
}

// ======================== 数据结构 ========================

type AppConfig struct {
	Servers         []ServerConfig `json:"servers"`
	CurrentServerID string         `json:"current_server_id"`
	BypassDomains   []string       `json:"bypass_domains"`
	BypassKeywords  []string       `json:"bypass_keywords"`
}

type ServerConfig struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	ServerAddr  string `json:"server"`
	ListenAddr  string `json:"listen"`
	Token       string `json:"token"`
	ServerIP    string `json:"ip"`
	DNSServer   string `json:"dns"`
	ECHDomain   string `json:"ech"`
	RoutingMode string `json:"routing"`
}

// ======================== 全局变量 ========================

var (
	logData      = binding.NewString()
	proxyRunning = binding.NewBool()

	statusText    = binding.NewString()
	latencyStr    = binding.NewString()
	
	// 流量统计
	speedUpStr    = binding.NewString()
	speedDownStr  = binding.NewString()
	totalStr      = binding.NewString()

	infoDetails    = binding.NewString() // 整合后的详情文本

	activeConfig  ServerConfig
	globalRules   AppConfig
	proxyListener net.Listener
	proxyCtx      context.Context
	proxyCancel   context.CancelFunc

	echListMu       sync.RWMutex
	echList         []byte
	chinaIPRangesMu sync.RWMutex
	chinaIPRanges   []ipRange

	totalUp   uint64
	totalDown uint64
	systemProxyEnabled bool
)

// ======================== 主程序 ========================

func main() {
	os.Setenv("FYNE_SCALE", "1.0")
	myApp := app.NewWithID("com.echworkers.client")
	myApp.SetIcon(theme.DefaultTheme().Icon(theme.IconNameHome))
	myApp.Settings().SetTheme(&CompactTheme{})

	w := myApp.NewWindow("ECH Client")
	w.Resize(fyne.NewSize(700, 450)) // 极度紧凑尺寸
	w.CenterOnScreen()

	config := loadConfig()
	initDefaultRules(&config)
	globalRules = config

	resetStats()
	go startStatsMonitor()

	// 构建界面
	dashboardTab := buildDashboard(w, &config)
	profileTab := buildProfileEditor(w, &config)
	advancedTab := buildAdvancedTab(&config)

	tabs := container.NewAppTabs(
		container.NewTabItemWithIcon("控制台", theme.HomeIcon(), dashboardTab),
		container.NewTabItemWithIcon("节点", theme.SettingsIcon(), profileTab),
		container.NewTabItemWithIcon("日志", theme.InfoIcon(), advancedTab),
	)
	tabs.SetTabLocation(container.TabLocationLeading)

	w.SetContent(tabs)
	w.SetCloseIntercept(func() { w.Hide() })
	
	if desk, ok := myApp.(desktop.App); ok {
		desk.SetSystemTrayMenu(fyne.NewMenu("ECH",
			fyne.NewMenuItem("显示", func() { w.Show() }),
			fyne.NewMenuItem("退出", func() {
				if systemProxyEnabled { setSystemProxy(false, activeConfig.ListenAddr, activeConfig.RoutingMode) }
				myApp.Quit()
			}),
		))
	}
	w.ShowAndRun()
}

// ======================== 紧凑界面构建 (重构核心) ========================

func buildDashboard(w fyne.Window, config *AppConfig) fyne.CanvasObject {
	// 1. 顶部状态栏
	statusDot := canvas.NewCircle(color.RGBA{200, 200, 200, 255})
	statusDot.Resize(fyne.NewSize(12, 12))
	statusDot.MinSize()
	
	statusLabel := widget.NewLabelWithData(statusText)
	statusLabel.TextStyle = fyne.TextStyle{Bold: true}
	
	latencyLabel := widget.NewLabelWithData(latencyStr)
	
	currentProfileLabel := widget.NewLabel("配置: " + getCurrentProfileName(config))
	currentProfileLabel.TextStyle = fyne.TextStyle{Monospace: true}
	
	topBar := container.NewHBox(
		statusDot, statusLabel, 
		widget.NewSeparator(),
		widget.NewIcon(theme.InfoIcon()), latencyLabel,
		layout.NewSpacer(),
		currentProfileLabel,
	)

	// 2. 核心流量仪表盘
	makeStatCard := func(title string, val binding.String, icon fyne.Resource, col color.Color) fyne.CanvasObject {
		vLabel := widget.NewLabelWithData(val)
		vLabel.TextStyle = fyne.TextStyle{Bold: true, Monospace: true}
		vLabel.Alignment = fyne.TextAlignCenter
		
		tLabel := canvas.NewText(title, col)
		tLabel.TextSize = 10
		tLabel.Alignment = fyne.TextAlignCenter
		
		return widget.NewCard("", "", container.NewVBox(
			container.NewCenter(widget.NewIcon(icon)),
			vLabel,
			container.NewCenter(tLabel),
		))
	}
	
	trafficGrid := container.NewGridWithColumns(3,
		makeStatCard("上传速度", speedUpStr, theme.UploadIcon(), theme.PrimaryColor()),
		makeStatCard("下载速度", speedDownStr, theme.DownloadIcon(), theme.PrimaryColor()),
		makeStatCard("总流量", totalStr, theme.HistoryIcon(), color.Gray{Y: 100}),
	)

	// 3. 控制与详情
	infoLabel := widget.NewLabelWithData(infoDetails)
	infoLabel.Wrapping = fyne.TextWrapWord
	
	// === 修复点：用 NewCard 代替 NewGroup ===
	infoCard := widget.NewCard("节点详情", "", infoLabel)

	startBtn := widget.NewButton("启动代理", nil)
	stopBtn := widget.NewButton("停止", nil)
	startBtn.Importance = widget.HighImportance // 蓝色高亮
	stopBtn.Disable()

	sysProxyCheck := widget.NewCheck("系统代理", func(checked bool) {
		systemProxyEnabled = checked
		if proxyListener != nil { setSystemProxy(checked, activeConfig.ListenAddr, activeConfig.RoutingMode) }
	})

	startBtn.OnTapped = func() {
		idx := getProfileIndex(config, config.CurrentServerID)
		if idx == -1 { dialog.ShowError(errors.New("无效配置"), w); return }
		activeConfig = config.Servers[idx]
		
		details := fmt.Sprintf("地址: %s\nECH: %s\n模式: %s\n监听: %s", 
			activeConfig.ServerAddr, activeConfig.ECHDomain, activeConfig.RoutingMode, activeConfig.ListenAddr)
		infoDetails.Set(details)
		currentProfileLabel.SetText("配置: " + activeConfig.Name)

		logData.Set(""); guiLog("正在启动...")
		if err := startProxyCore(); err != nil { guiLog("失败: %v", err); dialog.ShowError(err, w); return }

		proxyRunning.Set(true)
		statusText.Set("运行中")
		statusDot.FillColor = color.RGBA{0, 200, 0, 255}
		statusDot.Refresh()
		
		startBtn.Disable(); stopBtn.Enable()
		if systemProxyEnabled { setSystemProxy(true, activeConfig.ListenAddr, activeConfig.RoutingMode) }
		go latencyMonitorLoop()
	}

	stopBtn.OnTapped = func() {
		setSystemProxy(false, activeConfig.ListenAddr, activeConfig.RoutingMode)
		stopProxyCore()
		proxyRunning.Set(false)
		statusText.Set("已停止")
		statusDot.FillColor = color.RGBA{200, 50, 50, 255}
		statusDot.Refresh()
		
		startBtn.Enable(); stopBtn.Disable()
		latencyStr.Set("-")
		guiLog("服务已停止")
	}

	ctrlGrid := container.NewGridWithColumns(2, startBtn, stopBtn)
	
	mainContent := container.NewVBox(
		topBar,
		widget.NewSeparator(),
		trafficGrid,
		widget.NewSeparator(),
		infoCard,
		layout.NewSpacer(),
		sysProxyCheck,
		ctrlGrid,
	)

	return container.NewPadded(mainContent)
}

func buildProfileEditor(w fyne.Window, config *AppConfig) fyne.CanvasObject {
	nameEntry := widget.NewEntry(); serverEntry := widget.NewEntry()
	listenEntry := widget.NewEntry(); tokenEntry := widget.NewPasswordEntry()
	ipEntry := widget.NewEntry()
	
	routingSelect := widget.NewSelect([]string{"bypass_cn", "global", "none"}, nil)
	
	listData := binding.NewStringList()
	reloadList := func() {
		var names []string
		for _, s := range config.Servers { names = append(names, s.Name) }
		listData.Set(names)
	}
	reloadList()

	profileList := widget.NewListWithData(listData,
		func() fyne.CanvasObject { return widget.NewLabel("template") },
		func(i binding.DataItem, o fyne.CanvasObject) { o.(*widget.Label).Bind(i.(binding.String)) },
	)

	profileList.OnSelected = func(id widget.ListItemID) {
		if id >= len(config.Servers) { return }
		s := config.Servers[id]
		config.CurrentServerID = s.ID
		nameEntry.SetText(s.Name); serverEntry.SetText(s.ServerAddr)
		listenEntry.SetText(s.ListenAddr); tokenEntry.SetText(s.Token); ipEntry.SetText(s.ServerIP)
		routingSelect.SetSelected(s.RoutingMode)
	}

	saveBtn := widget.NewButtonWithIcon("保存", theme.DocumentSaveIcon(), func() {
		idx := getProfileIndex(config, config.CurrentServerID)
		if idx == -1 { return }
		s := &config.Servers[idx]
		s.Name = nameEntry.Text; s.ServerAddr = serverEntry.Text; s.ListenAddr = listenEntry.Text
		s.Token = tokenEntry.Text; s.ServerIP = ipEntry.Text; s.RoutingMode = routingSelect.Selected
		saveConfig(*config); reloadList()
	})

	newBtn := widget.NewButtonWithIcon("新建", theme.ContentAddIcon(), func() {
		newS := ServerConfig{ID: fmt.Sprintf("%d", time.Now().Unix()), Name: "新配置", ListenAddr: "127.0.0.1:30000", RoutingMode: "bypass_cn"}
		config.Servers = append(config.Servers, newS); config.CurrentServerID = newS.ID
		saveConfig(*config); reloadList(); profileList.Select(len(config.Servers)-1)
	})

	delBtn := widget.NewButtonWithIcon("删除", theme.DeleteIcon(), func() {
		if len(config.Servers) <= 1 { return }
		idx := getProfileIndex(config, config.CurrentServerID)
		if idx != -1 {
			config.Servers = append(config.Servers[:idx], config.Servers[idx+1:]...)
			config.CurrentServerID = config.Servers[0].ID
			saveConfig(*config); reloadList(); profileList.Select(0)
		}
	})

	form := widget.NewForm(
		widget.NewFormItem("名称", nameEntry), widget.NewFormItem("地址", serverEntry),
		widget.NewFormItem("端口", listenEntry), widget.NewFormItem("Token", tokenEntry),
		widget.NewFormItem("IP", ipEntry), widget.NewFormItem("模式", routingSelect),
	)

	return container.NewHSplit(
		container.NewBorder(nil, nil, nil, nil, widget.NewCard("列表", "", profileList)),
		container.NewBorder(nil, container.NewHBox(newBtn, saveBtn, delBtn), nil, nil, widget.NewCard("编辑", "", form)),
	)
}

func buildAdvancedTab(config *AppConfig) fyne.CanvasObject {
	logEntry := widget.NewMultiLineEntry()
	logEntry.TextStyle = fyne.TextStyle{Monospace: true}
	logEntry.Bind(logData)
	return container.NewGridWrap(fyne.NewSize(650, 350), logEntry)
}

// ======================== 抗封锁核心 ========================

func startProxyCore() error {
	atomic.StoreUint64(&totalUp, 0); atomic.StoreUint64(&totalDown, 0)
	if activeConfig.RoutingMode == "bypass_cn" { go loadChinaIPList() }
	if activeConfig.ECHDomain == "" { activeConfig.ECHDomain = "cloudflare-ech.com" }
	if activeConfig.DNSServer == "" { activeConfig.DNSServer = "dns.alidns.com/dns-query" }
	
	if err := prepareECH(activeConfig.ECHDomain, activeConfig.DNSServer); err != nil { return err }
	l, err := net.Listen("tcp", activeConfig.ListenAddr)
	if err != nil { return err }
	
	proxyListener = l
	proxyCtx, proxyCancel = context.WithCancel(context.Background())
	guiLog("服务启动: %s", activeConfig.ListenAddr)
	
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				select { case <-proxyCtx.Done(): return; default: time.Sleep(time.Second); continue }
			}
			go handleConnection(conn)
		}
	}()
	return nil
}

func stopProxyCore() {
	if proxyCancel != nil { proxyCancel() }
	if proxyListener != nil { proxyListener.Close() }
}

func handleConnection(conn net.Conn) {
	conn = &CountConn{Conn: conn}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil { return }
	if buf[0] == 0x05 { handleSOCKS5(conn) } else { handleHTTP(conn, buf[0]) }
}

func handleSOCKS5(conn net.Conn) {
	io.ReadFull(conn, make([]byte, 1))
	buf := make([]byte, 256); conn.Read(buf) 
	conn.Write([]byte{0x05, 0x00})
	if _, err := io.ReadFull(conn, buf[:4]); err != nil { return }
	cmd := buf[1]; atyp := buf[3]
	var host string
	switch atyp {
	case 1: io.ReadFull(conn, buf[:4]); host = net.IP(buf[:4]).String()
	case 3: io.ReadFull(conn, buf[:1]); l := int(buf[0]); io.ReadFull(conn, buf[:l]); host = string(buf[:l])
	case 4: io.ReadFull(conn, buf[:16]); host = net.IP(buf[:16]).String()
	}
	io.ReadFull(conn, buf[:2])
	target := fmt.Sprintf("%s:%d", host, binary.BigEndian.Uint16(buf[:2]))
	if cmd == 1 { startTunnel(conn, target, 1, "") } else { conn.Write([]byte{0x05, 0x07}) }
}

func handleHTTP(conn net.Conn, firstByte byte) {
	reader := bufio.NewReader(io.MultiReader(bytes.NewReader([]byte{firstByte}), conn))
	reqLine, err := reader.ReadString('\n')
	if err != nil { return }
	parts := strings.Fields(reqLine)
	if len(parts) < 2 { return }
	method, urlStr := parts[0], parts[1]
	if method == "CONNECT" {
		startTunnel(conn, urlStr, 2, "")
	} else {
		target := urlStr
		if u, err := url.Parse(urlStr); err == nil { target = u.Host; if !strings.Contains(target, ":") { target += ":80" } }
		var buf bytes.Buffer; buf.WriteString(reqLine)
		for {
			line, err := reader.ReadString('\n')
			if err != nil || line == "\r\n" { buf.WriteString("\r\n"); break }
			if !strings.HasPrefix(strings.ToLower(line), "proxy-") { buf.WriteString(line) }
		}
		if reader.Buffered() > 0 { b, _ := reader.Peek(reader.Buffered()); buf.Write(b) }
		startTunnel(conn, target, 3, buf.String())
	}
}

func startTunnel(conn net.Conn, target string, mode int, firstFrame string) {
	host, _, _ := net.SplitHostPort(target)
	if shouldBypass(host) {
		guiLog("[直连] %s", host)
		handleDirect(conn, target, mode, firstFrame)
		return
	}
	guiLog("[代理] %s", host)

	ws, err := dialWS(2)
	if err != nil { guiLog("[Error] %v", err); return }
	defer ws.Close()

	conn.SetDeadline(time.Time{})
	ws.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf("CONNECT:%s|%s", target, firstFrame)))
	_, msg, err := ws.ReadMessage()
	if err != nil || string(msg) != "CONNECTED" { return }

	if mode == 1 {
		conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0})
	} else if mode == 2 {
		conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	}

	done := make(chan struct{})
	var once sync.Once
	closeDone := func() { once.Do(func() { close(done) }) }

	// 随机心跳 (Anti-Censorship)
	go func() {
		for {
			r, _ := rand.Int(rand.Reader, big.NewInt(10000))
			interval := 10*time.Second + time.Duration(r.Int64())*time.Millisecond
			select {
			case <-time.After(interval): ws.WriteMessage(websocket.PingMessage, nil)
			case <-done: return
			}
		}
	}()
	go func() {
		defer closeDone()
		buf := make([]byte, 32*1024)
		for { n, err := conn.Read(buf); if err != nil { break }; ws.WriteMessage(websocket.BinaryMessage, buf[:n]) }
	}()
	for {
		mt, d, err := ws.ReadMessage()
		if err != nil { break }
		if mt == websocket.TextMessage && string(d) == "CLOSE" { break }
		if mt == websocket.BinaryMessage || mt == websocket.TextMessage { conn.Write(d) }
	}
	closeDone()
}

func handleDirect(conn net.Conn, target string, mode int, firstFrame string) {
	remote, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil { return }
	defer remote.Close()
	if mode == 1 {
		conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0})
	} else if mode == 2 {
		conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	}
	if firstFrame != "" { remote.Write([]byte(firstFrame)) }
	go io.Copy(remote, conn); io.Copy(conn, remote)
}

func prepareECH(domain, dns string) error {
	u, _ := url.Parse(dns); if u.Scheme == "" { u.Scheme = "https" }
	q := []byte{0,0, 1,0, 0,1, 0,0, 0,0, 0,0}
	for _, l := range strings.Split(domain, ".") { q = append(q, byte(len(l))); q = append(q, []byte(l)...) }
	q = append(q, 0, 0,65, 0,1)
	query := u.Query(); query.Set("dns", base64.RawURLEncoding.EncodeToString(q)); u.RawQuery = query.Encode()
	req, _ := http.NewRequest("GET", u.String(), nil); req.Header.Set("Accept", "application/dns-message")
	client := &http.Client{Timeout: 5*time.Second}; resp, err := client.Do(req)
	if err != nil { return err }
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if len(body) > 20 {
		for i := 0; i < len(body)-4; i++ {
			if body[i] == 0x00 && body[i+1] == 0x05 {
				l := int(body[i+2])<<8 | int(body[i+3])
				if i+4+l <= len(body) && l > 10 {
					echListMu.Lock(); echList = body[i+4 : i+4+l]; echListMu.Unlock(); return nil
				}
			}
		}
	}
	return nil
}

func dialWS(retry int) (*websocket.Conn, error) {
	for i:=0; i<retry; i++ {
		host, port, _ := net.SplitHostPort(activeConfig.ServerAddr)
		if host == "" { host = activeConfig.ServerAddr; port = "443" }
		echListMu.RLock(); el := echList; echListMu.RUnlock()
		if len(el) == 0 { prepareECH(activeConfig.ECHDomain, activeConfig.DNSServer) }
		roots, _ := x509.SystemCertPool()
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: host, RootCAs: roots}
		v := reflect.ValueOf(tlsCfg).Elem()
		if f := v.FieldByName("EncryptedClientHelloConfigList"); f.IsValid() { f.Set(reflect.ValueOf(el)) }
		if f := v.FieldByName("EncryptedClientHelloRejectionVerify"); f.IsValid() { f.Set(reflect.ValueOf(func(cs tls.ConnectionState) error { return errors.New("ECH Rejected") })) }
		
		d := websocket.Dialer{TLSClientConfig: tlsCfg, HandshakeTimeout: 5*time.Second}
		if activeConfig.Token != "" { d.Subprotocols = []string{activeConfig.Token} }
		if activeConfig.ServerIP != "" { d.NetDial = func(n, a string) (net.Conn, error) { return net.Dial(n, activeConfig.ServerIP+":"+port) } }
		
		headers := http.Header{}
		headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36")
		headers.Add("Origin", "https://"+host)
		c, _, err := d.Dial(fmt.Sprintf("wss://%s:%s/", host, port), headers)
		if err == nil { return c, nil }
		time.Sleep(500 * time.Millisecond)
	}
	return nil, errors.New("Dial fail")
}

type CountConn struct { net.Conn }
func (c *CountConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 { atomic.AddUint64(&totalUp, uint64(n)) }
	return n, err
}
func (c *CountConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 { atomic.AddUint64(&totalDown, uint64(n)) }
	return n, err
}

func resetStats() {
	statusText.Set("未连接"); latencyStr.Set("-")
	speedUpStr.Set("0 KB/s"); speedDownStr.Set("0 KB/s"); totalStr.Set("0 MB")
	infoDetails.Set("请选择节点启动")
}

func startStatsMonitor() {
	var lastUp, lastDown uint64
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		cUp := atomic.LoadUint64(&totalUp); cDown := atomic.LoadUint64(&totalDown)
		speedUpStr.Set(fmtBytes(cUp - lastUp) + "/s")
		speedDownStr.Set(fmtBytes(cDown - lastDown) + "/s")
		totalStr.Set(fmtBytes(cUp + cDown))
		lastUp, lastDown = cUp, cDown
	}
}

func latencyMonitorLoop() {
	for {
		isRunning, _ := proxyRunning.Get()
		if !isRunning { return }
		host, port, _ := net.SplitHostPort(activeConfig.ServerAddr)
		if host == "" { host = activeConfig.ServerAddr; port = "443" }
		target := host + ":" + port
		if activeConfig.ServerIP != "" { target = activeConfig.ServerIP + ":" + port }
		
		start := time.Now()
		conn, err := net.DialTimeout("tcp", target, 3*time.Second)
		if err != nil { latencyStr.Set("超时") } else {
			conn.Close(); latencyStr.Set(fmt.Sprintf("%dms", time.Since(start).Milliseconds()))
		}
		time.Sleep(5 * time.Second)
	}
}

func fmtBytes(b uint64) string {
	if b < 1024 { return fmt.Sprintf("%d B", b) }
	if b < 1024*1024 { return fmt.Sprintf("%.1f KB", float64(b)/1024) }
	if b < 1024*1024*1024 { return fmt.Sprintf("%.2f MB", float64(b)/1024/1024) }
	return fmt.Sprintf("%.2f GB", float64(b)/1024/1024/1024)
}

func loadConfig() AppConfig {
	var c AppConfig
	f, err := os.Open("config.json")
	if err != nil { return c }
	defer f.Close()
	json.NewDecoder(f).Decode(&c)
	return c
}
func saveConfig(c AppConfig) {
	f, _ := os.Create("config.json")
	e := json.NewEncoder(f); e.SetIndent("","  "); e.Encode(c); f.Close()
}
func getProfileIndex(c *AppConfig, id string) int { for i, s := range c.Servers { if s.ID == id { return i } }; return -1 }
func getCurrentProfileName(c *AppConfig) string { i := getProfileIndex(c, c.CurrentServerID); if i != -1 { return c.Servers[i].Name }; return "未选择" }

func initDefaultRules(cfg *AppConfig) {
	if len(cfg.BypassDomains) == 0 { cfg.BypassDomains = []string{".cn", ".top", ".local", "baidu.com", "qq.com", "163.com", "taobao.com", "jd.com"} }
	if len(cfg.BypassKeywords) == 0 { cfg.BypassKeywords = []string{"cn", "baidu", "tencent", "alibaba", "360", "bilibili"} }
}

func shouldBypass(host string) bool {
	if activeConfig.RoutingMode == "none" { return true }
	if activeConfig.RoutingMode == "global" { return false }
	domain := strings.ToLower(host)
	if h, _, err := net.SplitHostPort(domain); err == nil { domain = h }
	for _, suffix := range globalRules.BypassDomains { if strings.HasSuffix(domain, suffix) { return true } }
	for _, kw := range globalRules.BypassKeywords { if strings.Contains(domain, kw) { return true } }
	ip := net.ParseIP(domain)
	if ip == nil {
		if ips, err := net.LookupIP(domain); err == nil && len(ips) > 0 { ip = ips[0] }
	}
	if ip != nil && isChinaIP(ip) { return true }
	return false
}

func isChinaIP(ip net.IP) bool {
	v := binary.BigEndian.Uint32(ip.To4())
	chinaIPRangesMu.RLock()
	defer chinaIPRangesMu.RUnlock()
	l, r := 0, len(chinaIPRanges)
	for l < r {
		m := (l + r) / 2
		rg := chinaIPRanges[m]
		if v < rg.start { r = m } else if v > rg.end { l = m + 1 } else { return true }
	}
	return false
}

func loadChinaIPList() {
	path := "chn_ip.txt"
	if _, err := os.Stat(path); os.IsNotExist(err) {
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Get("https://raw.githubusercontent.com/mayaxcn/china-ip-list/refs/heads/master/chn_ip.txt")
		if err == nil {
			defer resp.Body.Close()
			content, _ := io.ReadAll(resp.Body)
			if len(content) > 0 { os.WriteFile(path, content, 0644) }
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
			list = append(list, ipRange{binary.BigEndian.Uint32(s.To4()), binary.BigEndian.Uint32(e.To4())})
		}
	}
	chinaIPRangesMu.Lock(); chinaIPRanges = list; chinaIPRangesMu.Unlock()
}

func guiLog(f string, args ...any) {
	s := fmt.Sprintf("[%s] %s\n", time.Now().Format("15:04"), fmt.Sprintf(f, args...))
	current, _ := logData.Get()
	if len(current) > 5000 { current = current[1000:] }
	logData.Set(current + s)
}

func setSystemProxy(enable bool, listen, mode string) bool {
	_, port, _ := net.SplitHostPort(listen)
	if port == "" { return false }
	if runtime.GOOS == "windows" {
		if enable {
			exec.Command("reg", "add", `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "1", "/f").Run()
			exec.Command("reg", "add", `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`, "/v", "ProxyServer", "/t", "REG_SZ", "/d", "127.0.0.1:"+port, "/f").Run()
		} else {
			exec.Command("reg", "add", `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "0", "/f").Run()
		}
		return true
	}
	return false
}
type ipRange struct { start, end uint32 }
