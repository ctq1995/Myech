package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	_ "embed" // 用于嵌入字体
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"image/color"
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

// ======================== 1. 资源嵌入与自定义主题 ========================

//go:embed font.ttf
var embedFontData []byte

// MyTheme 强制使用嵌入的中文字体
type MyTheme struct{}

var _ fyne.Theme = (*MyTheme)(nil)

func (m MyTheme) Font(s fyne.TextStyle) fyne.Resource {
	return &fyne.StaticResource{
		StaticName:    "font.ttf",
		StaticContent: embedFontData,
	}
}
func (m MyTheme) Color(n fyne.ThemeColorName, v fyne.ThemeVariant) color.Color {
	return theme.DefaultTheme().Color(n, v)
}
func (m MyTheme) Icon(n fyne.ThemeIconName) fyne.Resource { return theme.DefaultTheme().Icon(n) }
func (m MyTheme) Size(n fyne.ThemeSizeName) float32    { return theme.DefaultTheme().Size(n) }

// ======================== 2. 配置结构与全局变量 ========================

type AppConfig struct {
	Servers         []ServerConfig `json:"servers"`
	CurrentServerID string         `json:"current_server_id"`
	BypassDomains   []string       `json:"bypass_domains"`  // 域名后缀白名单
	BypassKeywords  []string       `json:"bypass_keywords"` // 关键词白名单
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

var (
	// UI Bindings
	logData      = binding.NewString()
	proxyRunning = binding.NewBool()
	statusText   = binding.NewString()
	speedUpStr   = binding.NewString()
	speedDownStr = binding.NewString()

	// Internal State
	activeConfig  ServerConfig
	globalRules   AppConfig
	proxyListener net.Listener
	proxyCtx      context.Context
	proxyCancel   context.CancelFunc

	// Caches
	echListMu       sync.RWMutex
	echList         []byte
	chinaIPRangesMu sync.RWMutex
	chinaIPRanges   []ipRange

	// Stats
	totalUp   uint64
	totalDown uint64

	systemProxyEnabled bool
)

// ======================== 3. GUI 主程序 ========================

func main() {
	os.Setenv("FYNE_SCALE", "1.1") // 适度放大 UI

	myApp := app.NewWithID("com.echworkers.client")
	myApp.Settings().SetTheme(&MyTheme{}) // 应用中文主题

	w := myApp.NewWindow("ECH Workers 客户端 Pro")
	w.Resize(fyne.NewSize(950, 680))
	w.CenterOnScreen()

	// 加载配置
	config := loadConfig()
	initDefaultRules(&config)
	globalRules = config

	// 初始化状态栏
	statusText.Set("状态: 未连接")
	speedUpStr.Set("↑ 0 KB/s")
	speedDownStr.Set("↓ 0 KB/s")
	go startSpeedMonitor()

	// === 构建 Tab 页面 ===
	dashboardTab := buildDashboard(w, &config)
	profileTab := buildProfileEditor(w, &config)
	advancedTab := buildAdvancedTab(&config)

	tabs := container.NewAppTabs(
		container.NewTabItemWithIcon("仪表盘", theme.HomeIcon(), dashboardTab),
		container.NewTabItemWithIcon("节点配置", theme.SettingsIcon(), profileTab),
		container.NewTabItemWithIcon("高级与日志", theme.InfoIcon(), advancedTab),
	)
	tabs.SetTabLocation(container.TabLocationLeading)

	w.SetContent(tabs)

	// 系统托盘
	if desk, ok := myApp.(desktop.App); ok {
		menu := fyne.NewMenu("ECH Client",
			fyne.NewMenuItem("显示主界面", func() { w.Show() }),
			fyne.NewMenuItem("退出", func() {
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

// ======================== UI 构建函数 ========================

func buildDashboard(w fyne.Window, config *AppConfig) fyne.CanvasObject {
	title := canvas.NewText("ECH 安全代理", theme.PrimaryColor())
	title.TextSize = 24
	title.TextStyle = fyne.TextStyle{Bold: true}

	statusLabel := widget.NewLabelWithData(statusText)
	statusLabel.TextStyle = fyne.TextStyle{Bold: true}

	speedBox := container.NewHBox(
		widget.NewIcon(theme.DownloadIcon()),
		widget.NewLabelWithData(speedDownStr),
		widget.NewIcon(theme.UploadIcon()),
		widget.NewLabelWithData(speedUpStr),
	)

	startBtn := widget.NewButtonWithIcon("启动代理", theme.MediaPlayIcon(), nil)
	stopBtn := widget.NewButtonWithIcon("停止服务", theme.MediaStopIcon(), nil)
	stopBtn.Disable()

	sysProxyCheck := widget.NewCheck("接管系统代理", func(checked bool) {
		systemProxyEnabled = checked
		if proxyListener != nil {
			setSystemProxy(checked, activeConfig.ListenAddr, activeConfig.RoutingMode)
		}
	})

	currentProfileLabel := widget.NewLabel("当前节点: " + getCurrentProfileName(config))

	startBtn.OnTapped = func() {
		idx := getProfileIndex(config, config.CurrentServerID)
		if idx == -1 {
			dialog.ShowError(errors.New("未选择有效配置"), w)
			return
		}
		activeConfig = config.Servers[idx]
		
		logData.Set("")
		guiLog("正在初始化 ECH 网络栈...")

		if err := startProxyCore(); err != nil {
			guiLog("启动失败: %v", err)
			dialog.ShowError(err, w)
			return
		}

		proxyRunning.Set(true)
		statusText.Set("状态: 运行中 - " + activeConfig.ListenAddr)
		startBtn.Disable()
		stopBtn.Enable()
		currentProfileLabel.SetText("运行节点: " + activeConfig.Name)

		if systemProxyEnabled {
			setSystemProxy(true, activeConfig.ListenAddr, activeConfig.RoutingMode)
		}
	}

	stopBtn.OnTapped = func() {
		setSystemProxy(false, activeConfig.ListenAddr, activeConfig.RoutingMode)
		stopProxyCore()
		
		proxyRunning.Set(false)
		statusText.Set("状态: 已停止")
		startBtn.Enable()
		stopBtn.Disable()
		guiLog("服务已停止")
	}

	ctrlCard := widget.NewCard("运行控制", "", container.NewVBox(
		statusLabel,
		speedBox,
		layout.NewSpacer(),
		sysProxyCheck,
		container.NewGridWithColumns(2, startBtn, stopBtn),
	))

	infoCard := widget.NewCard("信息面板", "", container.NewVBox(
		currentProfileLabel,
		widget.NewLabel("协议: ECH + WebSocket"),
		widget.NewLabel("分流: 智能识别 (域名+IP)"),
	))

	return container.NewVBox(
		container.NewHBox(title, layout.NewSpacer()),
		container.NewGridWithColumns(2, ctrlCard, infoCard),
	)
}

func buildProfileEditor(w fyne.Window, config *AppConfig) fyne.CanvasObject {
	nameEntry := widget.NewEntry()
	serverEntry := widget.NewEntry()
	serverEntry.SetPlaceHolder("xxx.workers.dev:443")
	listenEntry := widget.NewEntry()
	tokenEntry := widget.NewPasswordEntry()
	ipEntry := widget.NewEntry()
	ipEntry.SetPlaceHolder("优选IP (留空则自动解析)")
	
	routingSelect := widget.NewSelect([]string{"智能分流 (bypass_cn)", "全局代理 (global)", "直连 (none)"}, nil)
	
	listData := binding.NewStringList()
	reloadList := func() {
		var names []string
		for _, s := range config.Servers {
			names = append(names, s.Name)
		}
		listData.Set(names)
	}
	reloadList()

	profileList := widget.NewListWithData(listData,
		func() fyne.CanvasObject { return widget.NewLabel("template") },
		func(i binding.DataItem, o fyne.CanvasObject) {
			o.(*widget.Label).Bind(i.(binding.String))
		},
	)

	profileList.OnSelected = func(id widget.ListItemID) {
		if id >= len(config.Servers) { return }
		s := config.Servers[id]
		config.CurrentServerID = s.ID
		
		nameEntry.SetText(s.Name)
		serverEntry.SetText(s.ServerAddr)
		listenEntry.SetText(s.ListenAddr)
		tokenEntry.SetText(s.Token)
		ipEntry.SetText(s.ServerIP)
		
		mode := "智能分流 (bypass_cn)"
		if s.RoutingMode == "global" { mode = "全局代理 (global)" }
		if s.RoutingMode == "none" { mode = "直连 (none)" }
		routingSelect.SetSelected(mode)
	}

	saveBtn := widget.NewButtonWithIcon("保存修改", theme.DocumentSaveIcon(), func() {
		idx := getProfileIndex(config, config.CurrentServerID)
		if idx == -1 { return }

		s := &config.Servers[idx]
		s.Name = nameEntry.Text
		s.ServerAddr = serverEntry.Text
		s.ListenAddr = listenEntry.Text
		s.Token = tokenEntry.Text
		s.ServerIP = ipEntry.Text
		
		if strings.Contains(routingSelect.Selected, "global") { s.RoutingMode = "global" }
		if strings.Contains(routingSelect.Selected, "none") { s.RoutingMode = "none" }
		if strings.Contains(routingSelect.Selected, "bypass") { s.RoutingMode = "bypass_cn" }

		saveConfig(*config)
		reloadList()
		dialog.ShowInformation("提示", "配置已保存", w)
	})

	newBtn := widget.NewButtonWithIcon("新建配置", theme.ContentAddIcon(), func() {
		newS := ServerConfig{
			ID: fmt.Sprintf("%d", time.Now().Unix()), 
			Name: "新配置", 
			ListenAddr: "127.0.0.1:30000", 
			RoutingMode: "bypass_cn",
			ECHDomain: "cloudflare-ech.com",
			DNSServer: "dns.alidns.com/dns-query",
		}
		config.Servers = append(config.Servers, newS)
		config.CurrentServerID = newS.ID
		saveConfig(*config)
		reloadList()
		profileList.Select(len(config.Servers)-1)
	})

	delBtn := widget.NewButtonWithIcon("删除", theme.DeleteIcon(), func() {
		if len(config.Servers) <= 1 {
			dialog.ShowError(errors.New("至少保留一个配置"), w)
			return
		}
		idx := getProfileIndex(config, config.CurrentServerID)
		if idx != -1 {
			config.Servers = append(config.Servers[:idx], config.Servers[idx+1:]...)
			config.CurrentServerID = config.Servers[0].ID
			saveConfig(*config)
			reloadList()
			profileList.Select(0)
		}
	})

	form := widget.NewForm(
		widget.NewFormItem("配置名称", nameEntry),
		widget.NewFormItem("服务地址", serverEntry),
		widget.NewFormItem("本地端口", listenEntry),
		widget.NewFormItem("Token", tokenEntry),
		widget.NewFormItem("优选IP", ipEntry),
		widget.NewFormItem("分流模式", routingSelect),
	)

	editor := container.NewBorder(
		nil, 
		container.NewHBox(newBtn, saveBtn, delBtn), 
		nil, nil,
		widget.NewCard("编辑参数", "", form),
	)

	return container.NewHSplit(
		container.NewBorder(widget.NewLabel("配置列表"), nil, nil, nil, profileList),
		editor,
	)
}

func buildAdvancedTab(config *AppConfig) fyne.CanvasObject {
	logEntry := widget.NewMultiLineEntry()
	logEntry.TextStyle = fyne.TextStyle{Monospace: true}
	logEntry.Bind(logData)
	logArea := container.NewGridWrap(fyne.NewSize(800, 300), logEntry)

	rulesInfo := widget.NewLabel("此处显示内置的高级分流规则 (Domain/Keyword)\n这些规则存储在 config.json 中。\n默认包含: .cn, .top, baidu, qq, alibaba, 163 等")
	
	return container.NewVBox(
		widget.NewCard("运行日志", "", logArea),
		widget.NewCard("分流规则说明", "", rulesInfo),
	)
}

// ======================== 4. 网络核心与分流逻辑 ========================

func initDefaultRules(cfg *AppConfig) {
	if len(cfg.BypassDomains) == 0 {
		cfg.BypassDomains = []string{".cn", ".top", ".local", "baidu.com", "qq.com", "163.com", "taobao.com", "jd.com", "alipay.com", "zhihu.com", "csdn.net"}
	}
	if len(cfg.BypassKeywords) == 0 {
		cfg.BypassKeywords = []string{"cn", "baidu", "tencent", "alibaba", "360", "bilibili", "weibo"}
	}
}

func shouldBypass(host string) bool {
	if activeConfig.RoutingMode == "none" { return true }
	if activeConfig.RoutingMode == "global" { return false }
	
	domain := strings.ToLower(host)
	if h, _, err := net.SplitHostPort(domain); err == nil { domain = h }

	for _, suffix := range globalRules.BypassDomains {
		if strings.HasSuffix(domain, suffix) {
			guiLog("规则分流(后缀): %s -> 直连", domain)
			return true
		}
	}

	for _, kw := range globalRules.BypassKeywords {
		if strings.Contains(domain, kw) {
			guiLog("规则分流(关键词): %s -> 直连", domain)
			return true
		}
	}

	ip := net.ParseIP(domain)
	if ip == nil {
		if ips, err := net.LookupIP(domain); err == nil && len(ips) > 0 {
			ip = ips[0]
		}
	}

	if ip != nil && isChinaIP(ip) {
		guiLog("规则分流(GeoIP): %s -> 直连", domain)
		return true
	}

	return false
}

func startProxyCore() error {
	if activeConfig.RoutingMode == "bypass_cn" {
		go loadChinaIPList()
	}

	if activeConfig.ECHDomain == "" { activeConfig.ECHDomain = "cloudflare-ech.com" }
	if activeConfig.DNSServer == "" { activeConfig.DNSServer = "dns.alidns.com/dns-query" }
	
	guiLog("正在获取 ECH 配置 (%s)...", activeConfig.ECHDomain)
	if err := prepareECH(activeConfig.ECHDomain, activeConfig.DNSServer); err != nil {
		return err
	}

	l, err := net.Listen("tcp", activeConfig.ListenAddr)
	if err != nil { return err }
	
	proxyListener = l
	proxyCtx, proxyCancel = context.WithCancel(context.Background())

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				select {
				case <-proxyCtx.Done(): return
				default: time.Sleep(time.Second); continue
				}
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
	conn.SetDeadline(time.Now().Add(60 * time.Second))

	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil { return }
	
	if buf[0] == 0x05 {
		handleSOCKS5(conn)
	} else {
		handleHTTP(conn, buf[0])
	}
}

func handleSOCKS5(conn net.Conn) {
	io.ReadFull(conn, make([]byte, 1))
	buf := make([]byte, 256)
	conn.Read(buf) 
	conn.Write([]byte{0x05, 0x00})

	if _, err := io.ReadFull(conn, buf[:4]); err != nil { return }
	cmd := buf[1]
	atyp := buf[3]

	var host string
	switch atyp {
	case 1:
		io.ReadFull(conn, buf[:4])
		host = net.IP(buf[:4]).String()
	case 3:
		io.ReadFull(conn, buf[:1])
		domLen := int(buf[0])
		io.ReadFull(conn, buf[:domLen])
		host = string(buf[:domLen])
	case 4:
		io.ReadFull(conn, buf[:16])
		host = net.IP(buf[:16]).String()
	}

	io.ReadFull(conn, buf[:2])
	port := binary.BigEndian.Uint16(buf[:2])
	target := fmt.Sprintf("%s:%d", host, port)

	if cmd == 1 {
		startTunnel(conn, target, 1, "")
	} else {
		conn.Write([]byte{0x05, 0x07})
	}
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
		if u, err := url.Parse(urlStr); err == nil {
			target = u.Host
			if !strings.Contains(target, ":") { target += ":80" }
		}
		
		var buf bytes.Buffer
		buf.WriteString(reqLine)
		for {
			line, err := reader.ReadString('\n')
			if err != nil || line == "\r\n" { 
				buf.WriteString("\r\n")
				break 
			}
			if !strings.HasPrefix(strings.ToLower(line), "proxy-") {
				buf.WriteString(line)
			}
		}
		if reader.Buffered() > 0 {
			b, _ := reader.Peek(reader.Buffered())
			buf.Write(b)
		}
		
		startTunnel(conn, target, 3, buf.String())
	}
}

func startTunnel(conn net.Conn, target string, mode int, firstFrame string) {
	host, _, _ := net.SplitHostPort(target)
	if shouldBypass(host) {
		handleDirect(conn, target, mode, firstFrame)
		return
	}

	ws, err := dialWS(2)
	if err != nil {
		guiLog("WS 连接失败: %v", err)
		return
	}
	defer ws.Close()

	conn.SetDeadline(time.Time{})

	payload := fmt.Sprintf("CONNECT:%s|%s", target, firstFrame)
	ws.WriteMessage(websocket.TextMessage, []byte(payload))

	_, msg, err := ws.ReadMessage()
	if err != nil || string(msg) != "CONNECTED" { return }

	if mode == 1 {
		conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0})
	} else if mode == 2 {
		conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	}

	var mu sync.Mutex
	done := make(chan bool)

	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				mu.Lock()
				ws.WriteMessage(websocket.PingMessage, nil)
				mu.Unlock()
			case <-done: return
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
		close(done)
	}()

	for {
		mt, d, err := ws.ReadMessage()
		if err != nil { break }
		if mt == websocket.TextMessage && string(d) == "CLOSE" { break }
		if mt == websocket.BinaryMessage || mt == websocket.TextMessage {
			conn.Write(d)
		}
	}
	done<-true
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

	go io.Copy(remote, conn)
	io.Copy(conn, remote)
}

// ======================== 5. ECH & Utils ========================

func prepareECH(domain, dns string) error {
	u, _ := url.Parse(dns)
	if u.Scheme == "" { u.Scheme = "https" }
	
	q := []byte{0,0, 1,0, 0,1, 0,0, 0,0, 0,0} 
	for _, l := range strings.Split(domain, ".") {
		q = append(q, byte(len(l)))
		q = append(q, []byte(l)...)
	}
	q = append(q, 0, 0,65, 0,1)

	b64 := base64.RawURLEncoding.EncodeToString(q)
	query := u.Query()
	query.Set("dns", b64)
	u.RawQuery = query.Encode()

	req, _ := http.NewRequest("GET", u.String(), nil)
	req.Header.Set("Accept", "application/dns-message")
	
	client := &http.Client{Timeout: 5*time.Second}
	resp, err := client.Do(req)
	if err != nil { return err }
	defer resp.Body.Close()
	
	body, _ := io.ReadAll(resp.Body)
	if len(body) > 20 {
		for i := 0; i < len(body)-4; i++ {
			if body[i] == 0x00 && body[i+1] == 0x05 { 
				l := int(body[i+2])<<8 | int(body[i+3])
				if i+4+l <= len(body) && l > 10 {
					echListMu.Lock()
					echList = body[i+4 : i+4+l]
					echListMu.Unlock()
					return nil
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

		echListMu.RLock()
		el := echList
		echListMu.RUnlock()
		if len(el) == 0 { prepareECH(activeConfig.ECHDomain, activeConfig.DNSServer) }

		roots, _ := x509.SystemCertPool()
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: host, RootCAs: roots}
		
		v := reflect.ValueOf(tlsCfg).Elem()
		if f := v.FieldByName("EncryptedClientHelloConfigList"); f.IsValid() {
			f.Set(reflect.ValueOf(el))
		}
		if f := v.FieldByName("EncryptedClientHelloRejectionVerify"); f.IsValid() {
			f.Set(reflect.ValueOf(func(cs tls.ConnectionState) error { return errors.New("ECH Rejected") }))
		}

		d := websocket.Dialer{TLSClientConfig: tlsCfg, HandshakeTimeout: 5*time.Second}
		if activeConfig.Token != "" { d.Subprotocols = []string{activeConfig.Token} }
		if activeConfig.ServerIP != "" {
			d.NetDial = func(n, a string) (net.Conn, error) { return net.Dial(n, activeConfig.ServerIP+":"+port) }
		}

		c, _, err := d.Dial(fmt.Sprintf("wss://%s:%s/", host, port), nil)
		if err == nil { return c, nil }
		time.Sleep(500 * time.Millisecond)
	}
	return nil, errors.New("Dial fail")
}

type CountConn struct { net.Conn }
func (c *CountConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	atomic.AddUint64(&totalDown, uint64(n))
	return n, err
}
func (c *CountConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	atomic.AddUint64(&totalUp, uint64(n))
	return n, err
}

func startSpeedMonitor() {
	var lastU, lastD uint64
	for range time.Tick(1 * time.Second) {
		curU := atomic.LoadUint64(&totalUp)
		curD := atomic.LoadUint64(&totalDown)
		speedUpStr.Set(fmt.Sprintf("↑ %s/s", fmtBytes(curU-lastU)))
		speedDownStr.Set(fmt.Sprintf("↓ %s/s", fmtBytes(curD-lastD)))
		lastU, lastD = curU, curD
	}
}

func fmtBytes(b uint64) string {
	if b < 1024 { return fmt.Sprintf("%d B", b) }
	if b < 1024*1024 { return fmt.Sprintf("%.1f KB", float64(b)/1024) }
	return fmt.Sprintf("%.1f MB", float64(b)/1024/1024)
}

func guiLog(f string, args ...any) {
	s := fmt.Sprintf("[%s] %s\n", time.Now().Format("15:04:05"), fmt.Sprintf(f, args...))
	current, _ := logData.Get()
	if len(current) > 10000 { current = current[5000:] }
	logData.Set(current + s)
}

func loadConfig() AppConfig {
	var c AppConfig
	f, _ := os.Open("config.json")
	json.NewDecoder(f).Decode(&c)
	f.Close()
	return c
}
func saveConfig(c AppConfig) {
	f, _ := os.Create("config.json")
	e := json.NewEncoder(f)
	e.SetIndent("","  ")
	e.Encode(c)
	f.Close()
}
func getProfileIndex(c *AppConfig, id string) int {
	for i, s := range c.Servers { if s.ID == id { return i } }
	return -1
}
func getCurrentProfileName(c *AppConfig) string {
	i := getProfileIndex(c, c.CurrentServerID)
	if i != -1 { return c.Servers[i].Name }
	return "未选择"
}

func isChinaIP(ip net.IP) bool {
	v := binary.BigEndian.Uint32(ip.To4())
	chinaIPRangesMu.RLock()
	defer chinaIPRangesMu.RUnlock()
	l, r := 0, len(chinaIPRanges)
	for l < r {
		m := (l+r)/2
		if v < chinaIPRanges[m].start { r = m } else if v > chinaIPRanges[m].end { l = m+1 } else { return true }
	}
	return false
}

func loadChinaIPList() {
	path := "chn_ip.txt"
	if _, err := os.Stat(path); os.IsNotExist(err) {
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
	guiLog("已加载 %d 条中国 IP 规则", len(list))
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
