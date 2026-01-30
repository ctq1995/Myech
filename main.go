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
	if n == theme.ColorNamePrimary {
		return color.RGBA{R: 0, G: 110, B: 220, A: 255}
	}
	if n == theme.ColorNameBackground {
		return color.RGBA{R: 248, G: 248, B: 250, A: 255}
	}
	return theme.DefaultTheme().Color(n, theme.VariantLight)
}

func (m CompactTheme) Icon(n fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(n)
}

func (m CompactTheme) Size(n fyne.ThemeSizeName) float32 {
	if n == theme.SizeNamePadding {
		return 2
	}
	if n == theme.SizeNameText {
		return 12
	}
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

type ipRange struct {
	start, end uint32
}

// ======================== 全局变量 ========================

var (
	logData      = binding.NewString()
	proxyRunning = binding.NewBool()

	statusText = binding.NewString()
	latencyStr = binding.NewString()

	speedUpStr   = binding.NewString()
	speedDownStr = binding.NewString()
	totalStr     = binding.NewString()

	infoDetails = binding.NewString()

	activeConfig  ServerConfig
	globalRules   AppConfig
	proxyListener net.Listener
	proxyCtx      context.Context
	proxyCancel   context.CancelFunc

	echListMu       sync.RWMutex
	echList         []byte
	chinaIPRangesMu sync.RWMutex
	chinaIPRanges   []ipRange

	totalUp            uint64
	totalDown          uint64
	systemProxyEnabled bool
)

// ======================== 主程序 ========================

func main() {

	os.Setenv("FYNE_SCALE", "1.0")
	myApp := app.NewWithID("com.echworkers.client")
	myApp.SetIcon(theme.DefaultTheme().Icon(theme.IconNameHome))
	myApp.Settings().SetTheme(&CompactTheme{})
	checkECHSupport()

	w := myApp.NewWindow("ECH Client")
	w.Resize(fyne.NewSize(700, 450))
	w.CenterOnScreen()

	config := loadConfig()
	initDefaultRules(&config)
	globalRules = config

	resetStats()
	go startStatsMonitor()

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
				if systemProxyEnabled {
					setSystemProxy(false, activeConfig.ListenAddr, activeConfig.RoutingMode)
				}
				myApp.Quit()
			}),
		))
	}
	w.ShowAndRun()
}

// ======================== ECH 支持检测 ========================

func checkECHSupport() {
	tlsCfg := &tls.Config{}
	v := reflect.ValueOf(tlsCfg).Elem()
	f := v.FieldByName("EncryptedClientHelloConfigList")

	if f.IsValid() && f.CanSet() {
		guiLog("[信息] ✓ Go版本支持ECH (Go %s)", runtime.Version())
	} else {
		guiLog("[错误] ✗ Go版本不支持ECH (Go %s)，需要 Go 1.23+", runtime.Version())
	}
}

// ======================== 界面构建 ========================

func buildDashboard(w fyne.Window, config *AppConfig) fyne.CanvasObject {
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

	infoLabel := widget.NewLabelWithData(infoDetails)
	infoLabel.Wrapping = fyne.TextWrapWord

	// ✅ 添加滚动到详情卡片
	infoScroll := container.NewScroll(infoLabel)
	infoScroll.SetMinSize(fyne.NewSize(0, 120))
	
	infoCard := widget.NewCard("节点详情", "", infoScroll)

	startBtn := widget.NewButton("启动代理", nil)
	stopBtn := widget.NewButton("停止", nil)
	startBtn.Importance = widget.HighImportance
	stopBtn.Disable()

	sysProxyCheck := widget.NewCheck("系统代理", func(checked bool) {
		systemProxyEnabled = checked
		if proxyListener != nil {
			setSystemProxy(checked, activeConfig.ListenAddr, activeConfig.RoutingMode)
		}
	})

	startBtn.OnTapped = func() {
		idx := getProfileIndex(config, config.CurrentServerID)
		if idx == -1 {
			dialog.ShowError(errors.New("无效配置"), w)
			return
		}
		activeConfig = config.Servers[idx]

		// ✅ 显示更详细的配置信息
		details := fmt.Sprintf("服务器: %s\n监听地址: %s\nECH域名: %s\nDNS服务器: %s\n路由模式: %s",
			activeConfig.ServerAddr, 
			activeConfig.ListenAddr, 
			activeConfig.ECHDomain, 
			activeConfig.DNSServer,
			activeConfig.RoutingMode)
		
		if activeConfig.ServerIP != "" {
			details += fmt.Sprintf("\n指定IP: %s", activeConfig.ServerIP)
		}
		
		infoDetails.Set(details)
		currentProfileLabel.SetText("配置: " + activeConfig.Name)

		logData.Set("")
		guiLog("正在启动...")
		if err := startProxyCore(); err != nil {
			guiLog("失败: %v", err)
			dialog.ShowError(err, w)
			return
		}

		proxyRunning.Set(true)
		statusText.Set("运行中")
		statusDot.FillColor = color.RGBA{0, 200, 0, 255}
		statusDot.Refresh()

		startBtn.Disable()
		stopBtn.Enable()
		if systemProxyEnabled {
			setSystemProxy(true, activeConfig.ListenAddr, activeConfig.RoutingMode)
		}
		go latencyMonitorLoop()
	}

	stopBtn.OnTapped = func() {
		setSystemProxy(false, activeConfig.ListenAddr, activeConfig.RoutingMode)
		stopProxyCore()
		proxyRunning.Set(false)
		statusText.Set("已停止")
		statusDot.FillColor = color.RGBA{200, 50, 50, 255}
		statusDot.Refresh()

		startBtn.Enable()
		stopBtn.Disable()
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
	nameEntry := widget.NewEntry()
	serverEntry := widget.NewEntry()
	listenEntry := widget.NewEntry()
	tokenEntry := widget.NewPasswordEntry()
	ipEntry := widget.NewEntry()
	
	// ✅ 新增：ECH 和 DNS 配置
	echEntry := widget.NewEntry()
	echEntry.SetPlaceHolder("cloudflare-ech.com")
	
	dnsEntry := widget.NewEntry()
	dnsEntry.SetPlaceHolder("dns.alidns.com/dns-query")

	routingSelect := widget.NewSelect([]string{"bypass_cn", "global", "none"}, nil)

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
		if id >= len(config.Servers) {
			return
		}
		s := config.Servers[id]
		config.CurrentServerID = s.ID
		nameEntry.SetText(s.Name)
		serverEntry.SetText(s.ServerAddr)
		listenEntry.SetText(s.ListenAddr)
		tokenEntry.SetText(s.Token)
		ipEntry.SetText(s.ServerIP)
		
		// ✅ 加载 ECH 和 DNS 配置
		echEntry.SetText(s.ECHDomain)
		dnsEntry.SetText(s.DNSServer)
		
		routingSelect.SetSelected(s.RoutingMode)
	}

	saveBtn := widget.NewButtonWithIcon("保存", theme.DocumentSaveIcon(), func() {
		idx := getProfileIndex(config, config.CurrentServerID)
		if idx == -1 {
			return
		}
		s := &config.Servers[idx]
		s.Name = nameEntry.Text
		s.ServerAddr = serverEntry.Text
		s.ListenAddr = listenEntry.Text
		s.Token = tokenEntry.Text
		s.ServerIP = ipEntry.Text
		
		// ✅ 保存 ECH 和 DNS 配置
		s.ECHDomain = echEntry.Text
		if s.ECHDomain == "" {
			s.ECHDomain = "cloudflare-ech.com"
		}
		s.DNSServer = dnsEntry.Text
		if s.DNSServer == "" {
			s.DNSServer = "dns.alidns.com/dns-query"
		}
		
		s.RoutingMode = routingSelect.Selected
		saveConfig(*config)
		reloadList()
		dialog.ShowInformation("成功", "配置已保存", w)
	})

	newBtn := widget.NewButtonWithIcon("新建", theme.ContentAddIcon(), func() {
		newS := ServerConfig{
			ID:          fmt.Sprintf("%d", time.Now().Unix()),
			Name:        "新配置",
			ListenAddr:  "127.0.0.1:30000",
			RoutingMode: "bypass_cn",
			ECHDomain:   "cloudflare-ech.com",
			DNSServer:   "dns.alidns.com/dns-query",
		}
		config.Servers = append(config.Servers, newS)
		config.CurrentServerID = newS.ID
		saveConfig(*config)
		reloadList()
		profileList.Select(len(config.Servers) - 1)
	})

	delBtn := widget.NewButtonWithIcon("删除", theme.DeleteIcon(), func() {
		if len(config.Servers) <= 1 {
			dialog.ShowInformation("提示", "至少保留一个配置", w)
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

	// ✅ 优化表单布局，添加滚动
	form := widget.NewForm(
		widget.NewFormItem("节点名称", nameEntry),
		widget.NewFormItem("服务器地址", serverEntry),
		widget.NewFormItem("监听地址", listenEntry),
		widget.NewFormItem("Token", tokenEntry),
		widget.NewFormItem("指定IP", ipEntry),
		widget.NewFormItem("ECH域名", echEntry),
		widget.NewFormItem("DNS服务器", dnsEntry),
		widget.NewFormItem("路由模式", routingSelect),
	)

	// ✅ 添加滚动容器
	formScroll := container.NewScroll(form)
	formScroll.SetMinSize(fyne.NewSize(400, 350))

	return container.NewHSplit(
		container.NewBorder(nil, nil, nil, nil, widget.NewCard("节点列表", "", profileList)),
		container.NewBorder(
			nil, 
			container.NewHBox(newBtn, saveBtn, delBtn), 
			nil, 
			nil, 
			widget.NewCard("配置编辑", "", formScroll),
		),
	)
}

func buildAdvancedTab(config *AppConfig) fyne.CanvasObject {
	logEntry := widget.NewMultiLineEntry()
	logEntry.TextStyle = fyne.TextStyle{Monospace: true}
	logEntry.Wrapping = fyne.TextWrapWord
	logEntry.Bind(logData)

	// ✅ 添加滚动和边框，限制高度
	logScroll := container.NewScroll(logEntry)
	
	// ✅ 添加清空日志按钮
	clearBtn := widget.NewButton("清空日志", func() {
		logData.Set("")
	})

	// ✅ 添加日志级别过滤（可选）
	filterSelect := widget.NewSelect([]string{"全部", "成功", "警告", "错误"}, func(s string) {
		// 可以在这里实现日志过滤逻辑
	})
	filterSelect.SetSelected("全部")

	topBar := container.NewBorder(
		nil, nil,
		widget.NewLabel("过滤:"),
		clearBtn,
		filterSelect,
	)

	// ✅ 使用 Border 布局，顶部是工具栏，中间是日志
	return container.NewBorder(
		topBar,
		nil,
		nil,
		nil,
		logScroll,
	)
}


// ======================== 核心逻辑 ========================

func startProxyCore() error {
	atomic.StoreUint64(&totalUp, 0)
	atomic.StoreUint64(&totalDown, 0)

	if activeConfig.RoutingMode == "bypass_cn" {
		go loadChinaIPList()
	}

	if activeConfig.ECHDomain == "" {
		activeConfig.ECHDomain = "cloudflare-ech.com"
	}
	if activeConfig.DNSServer == "" {
		activeConfig.DNSServer = "dns.alidns.com/dns-query"
	}

	if err := prepareECH(activeConfig.ECHDomain, activeConfig.DNSServer); err != nil {
		return err
	}

	l, err := net.Listen("tcp", activeConfig.ListenAddr)
	if err != nil {
		return err
	}

	proxyListener = l
	proxyCtx, proxyCancel = context.WithCancel(context.Background())
	guiLog("服务启动: %s", activeConfig.ListenAddr)

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				select {
				case <-proxyCtx.Done():
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

func handleConnection(conn net.Conn) {
	conn = &CountConn{Conn: conn}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}

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

	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		return
	}

	cmd := buf[1]
	atyp := buf[3]
	var host string

	switch atyp {
	case 1:
		io.ReadFull(conn, buf[:4])
		host = net.IP(buf[:4]).String()
	case 3:
		io.ReadFull(conn, buf[:1])
		l := int(buf[0])
		io.ReadFull(conn, buf[:l])
		host = string(buf[:l])
	case 4:
		io.ReadFull(conn, buf[:16])
		host = net.IP(buf[:16]).String()
	}

	io.ReadFull(conn, buf[:2])
	target := fmt.Sprintf("%s:%d", host, binary.BigEndian.Uint16(buf[:2]))

	if cmd == 1 {
		startTunnel(conn, target, 1, "")
	} else {
		conn.Write([]byte{0x05, 0x07})
	}
}

func handleHTTP(conn net.Conn, firstByte byte) {
	reader := bufio.NewReader(io.MultiReader(bytes.NewReader([]byte{firstByte}), conn))
	reqLine, err := reader.ReadString('\n')
	if err != nil {
		return
	}

	parts := strings.Fields(reqLine)
	if len(parts) < 2 {
		return
	}

	method, urlStr := parts[0], parts[1]

	if method == "CONNECT" {
		startTunnel(conn, urlStr, 2, "")
	} else {
		target := urlStr
		if u, err := url.Parse(urlStr); err == nil {
			target = u.Host
			if !strings.Contains(target, ":") {
				target += ":80"
			}
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
		guiLog("[直连] %s", host)
		handleDirect(conn, target, mode, firstFrame)
		return
	}
	guiLog("[代理] %s", host)

	ws, err := dialWS(2)
	if err != nil {
		guiLog("[Error] %v", err)
		return
	}
	defer ws.Close()

	conn.SetDeadline(time.Time{})
	ws.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf("CONNECT:%s|%s", target, firstFrame)))

	_, msg, err := ws.ReadMessage()
	if err != nil || string(msg) != "CONNECTED" {
		return
	}

	if mode == 1 {
		conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	} else if mode == 2 {
		conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	}

	done := make(chan struct{})
	var once sync.Once
	closeDone := func() {
		once.Do(func() { close(done) })
	}

	go func() {
		for {
			r, _ := rand.Int(rand.Reader, big.NewInt(10000))
			interval := 10*time.Second + time.Duration(r.Int64())*time.Millisecond
			select {
			case <-time.After(interval):
				ws.WriteMessage(websocket.PingMessage, nil)
			case <-done:
				return
			}
		}
	}()

	go func() {
		defer closeDone()
		buf := make([]byte, 32*1024)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				break
			}
			ws.WriteMessage(websocket.BinaryMessage, buf[:n])
		}
	}()

	for {
		mt, d, err := ws.ReadMessage()
		if err != nil {
			break
		}
		if mt == websocket.TextMessage && string(d) == "CLOSE" {
			break
		}
		if mt == websocket.BinaryMessage || mt == websocket.TextMessage {
			conn.Write(d)
		}
	}
	closeDone()
}

func handleDirect(conn net.Conn, target string, mode int, firstFrame string) {
	remote, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
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

// ======================== ECH 支持 ========================

func setECHConfig(config *tls.Config, echList []byte) error {
	configValue := reflect.ValueOf(config).Elem()

	field1 := configValue.FieldByName("EncryptedClientHelloConfigList")
	if !field1.IsValid() || !field1.CanSet() {
		return fmt.Errorf("EncryptedClientHelloConfigList 字段不可用，需要 Go 1.23+")
	}
	field1.Set(reflect.ValueOf(echList))

	field2 := configValue.FieldByName("EncryptedClientHelloRejectionVerify")
	if !field2.IsValid() || !field2.CanSet() {
		return fmt.Errorf("EncryptedClientHelloRejectionVerify 字段不可用，需要 Go 1.23+")
	}
	rejectionFunc := func(cs tls.ConnectionState) error {
		guiLog("[警告] 服务器拒绝 ECH")
		return errors.New("服务器拒绝 ECH")
	}
	field2.Set(reflect.ValueOf(rejectionFunc))

	return nil
}

func buildTLSConfigWithECH(serverName string, echList []byte) (*tls.Config, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("加载系统根证书失败: %w", err)
	}

	if echList == nil || len(echList) == 0 {
		return nil, errors.New("ECH 配置为空")
	}

	config := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: serverName,
		RootCAs:    roots,
	}

	if err := setECHConfig(config, echList); err != nil {
		return nil, fmt.Errorf("设置 ECH 配置失败: %w", err)
	}

	return config, nil
}

func refreshECH() error {
	guiLog("[ECH] 正在刷新配置...")
	return prepareECH(activeConfig.ECHDomain, activeConfig.DNSServer)
}

func getECHList() ([]byte, error) {
	echListMu.RLock()
	defer echListMu.RUnlock()
	if len(echList) == 0 {
		return nil, errors.New("ECH 配置未加载")
	}
	return echList, nil
}

func prepareECH(domain, dns string) error {
	guiLog("[ECH] 正在获取配置: domain=%s, dns=%s", domain, dns)

	echBase64, err := queryHTTPSRecord(domain, dns)
	if err != nil {
		return fmt.Errorf("DNS 查询失败: %w", err)
	}
	if echBase64 == "" {
		return errors.New("未找到 ECH 参数")
	}

	raw, err := base64.StdEncoding.DecodeString(echBase64)
	if err != nil {
		return fmt.Errorf("ECH 解码失败: %w", err)
	}

	echListMu.Lock()
	echList = raw
	echListMu.Unlock()

	guiLog("[成功] ECH 配置已加载，长度: %d 字节", len(raw))
	return nil
}

func queryHTTPSRecord(domain, dnsServer string) (string, error) {
	dohURL := dnsServer
	if !strings.HasPrefix(dohURL, "https://") && !strings.HasPrefix(dohURL, "http://") {
		dohURL = "https://" + dohURL
	}
	return queryDoH(domain, dohURL)
}

func queryDoH(domain, dohURL string) (string, error) {
	u, err := url.Parse(dohURL)
	if err != nil {
		return "", fmt.Errorf("无效的 DoH URL: %v", err)
	}

	const typeHTTPS = 65
	dnsQuery := buildDNSQuery(domain, typeHTTPS)
	dnsBase64 := base64.RawURLEncoding.EncodeToString(dnsQuery)

	q := u.Query()
	q.Set("dns", dnsBase64)
	u.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return "", fmt.Errorf("创建请求失败: %v", err)
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("DoH 请求失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("DoH 服务器返回错误: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("读取 DoH 响应失败: %v", err)
	}

	return parseDNSResponse(body)
}

func buildDNSQuery(domain string, qtype uint16) []byte {
	query := make([]byte, 0, 512)
	query = append(query, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	for _, label := range strings.Split(domain, ".") {
		query = append(query, byte(len(label)))
		query = append(query, []byte(label)...)
	}
	query = append(query, 0x00, byte(qtype>>8), byte(qtype), 0x00, 0x01)
	return query
}

func parseDNSResponse(response []byte) (string, error) {
	if len(response) < 12 {
		return "", errors.New("响应过短")
	}
	ancount := binary.BigEndian.Uint16(response[6:8])
	if ancount == 0 {
		return "", errors.New("无应答记录")
	}

	offset := 12
	for offset < len(response) && response[offset] != 0 {
		offset += int(response[offset]) + 1
	}
	offset += 5

	const typeHTTPS = 65
	for i := 0; i < int(ancount); i++ {
		if offset >= len(response) {
			break
		}
		if response[offset]&0xC0 == 0xC0 {
			offset += 2
		} else {
			for offset < len(response) && response[offset] != 0 {
				offset += int(response[offset]) + 1
			}
			offset++
		}
		if offset+10 > len(response) {
			break
		}
		rrType := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 8
		dataLen := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 2
		if offset+int(dataLen) > len(response) {
			break
		}
		data := response[offset : offset+int(dataLen)]
		offset += int(dataLen)

		if rrType == typeHTTPS {
			if ech := parseHTTPSRecord(data); ech != "" {
				return ech, nil
			}
		}
	}
	return "", nil
}

func parseHTTPSRecord(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	offset := 2
	if offset < len(data) && data[offset] == 0 {
		offset++
	} else {
		for offset < len(data) && data[offset] != 0 {
			offset += int(data[offset]) + 1
		}
		offset++
	}
	for offset+4 <= len(data) {
		key := binary.BigEndian.Uint16(data[offset : offset+2])
		length := binary.BigEndian.Uint16(data[offset+2 : offset+4])
		offset += 4
		if offset+int(length) > len(data) {
			break
		}
		value := data[offset : offset+int(length)]
		offset += int(length)
		if key == 5 {
			return base64.StdEncoding.EncodeToString(value)
		}
	}
	return ""
}

// ======================== WebSocket 拨号 ========================

func dialWS(maxRetries int) (*websocket.Conn, error) {
	host, port, _ := net.SplitHostPort(activeConfig.ServerAddr)
	if host == "" {
		host = activeConfig.ServerAddr
		port = "443"
	}

	wsURL := fmt.Sprintf("wss://%s:%s/", host, port)

	for attempt := 1; attempt <= maxRetries; attempt++ {
		guiLog("[调试] 尝试连接 (%d/%d): %s", attempt, maxRetries, wsURL)

		echBytes, echErr := getECHList()
		if echErr != nil {
			if attempt < maxRetries {
				guiLog("[警告] ECH 配置未加载，尝试刷新...")
				refreshECH()
				time.Sleep(500 * time.Millisecond)
				continue
			}
			return nil, fmt.Errorf("ECH 配置错误: %w", echErr)
		}

		tlsCfg, tlsErr := buildTLSConfigWithECH(host, echBytes)
		if tlsErr != nil {
			return nil, fmt.Errorf("构建 TLS 配置失败: %w", tlsErr)
		}

		guiLog("[成功] TLS 配置已构建，ECH 长度: %d", len(echBytes))

		dialer := websocket.Dialer{
			TLSClientConfig:  tlsCfg,
			HandshakeTimeout: 15 * time.Second,
		}

		if activeConfig.Token != "" {
			dialer.Subprotocols = []string{activeConfig.Token}
			guiLog("[调试] 使用 Token 认证")
		}

		if activeConfig.ServerIP != "" {
			dialer.NetDial = func(network, address string) (net.Conn, error) {
				_, port, err := net.SplitHostPort(address)
				if err != nil {
					return nil, err
				}
				targetAddr := net.JoinHostPort(activeConfig.ServerIP, port)
				guiLog("[调试] 连接到指定 IP: %s", targetAddr)
				return net.DialTimeout(network, targetAddr, 10*time.Second)
			}
		}

		wsConn, _, dialErr := dialer.Dial(wsURL, nil)
		if dialErr != nil {
			if strings.Contains(dialErr.Error(), "ECH") && attempt < maxRetries {
				guiLog("[错误] ECH 连接失败，尝试刷新配置: %v", dialErr)
				refreshECH()
				time.Sleep(time.Second)
				continue
			}

			guiLog("[错误] 连接失败 (%d/%d): %v", attempt, maxRetries, dialErr)
			if attempt < maxRetries {
				time.Sleep(time.Duration(attempt) * time.Second)
				continue
			}
			return nil, fmt.Errorf("连接失败(已重试%d次): %w", maxRetries, dialErr)
		}

		guiLog("[成功] ✓ WebSocket 连接已建立")
		return wsConn, nil
	}

	return nil, errors.New("连接失败，已达最大重试次数")
}

// ======================== 流量统计 ========================

type CountConn struct {
	net.Conn
}

func (c *CountConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		atomic.AddUint64(&totalUp, uint64(n))
	}
	return n, err
}

func (c *CountConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		atomic.AddUint64(&totalDown, uint64(n))
	}
	return n, err
}

func resetStats() {
	statusText.Set("未连接")
	latencyStr.Set("-")
	speedUpStr.Set("0 KB/s")
	speedDownStr.Set("0 KB/s")
	totalStr.Set("0 MB")
	infoDetails.Set("请选择节点启动")
}

func startStatsMonitor() {
	var lastUp, lastDown uint64
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		cUp := atomic.LoadUint64(&totalUp)
		cDown := atomic.LoadUint64(&totalDown)
		speedUpStr.Set(fmtBytes(cUp-lastUp) + "/s")
		speedDownStr.Set(fmtBytes(cDown-lastDown) + "/s")
		totalStr.Set(fmtBytes(cUp + cDown))
		lastUp, lastDown = cUp, cDown
	}
}

func latencyMonitorLoop() {
	for {
		isRunning, _ := proxyRunning.Get()
		if !isRunning {
			return
		}
		host, port, _ := net.SplitHostPort(activeConfig.ServerAddr)
		if host == "" {
			host = activeConfig.ServerAddr
			port = "443"
		}
		target := host + ":" + port
		if activeConfig.ServerIP != "" {
			target = activeConfig.ServerIP + ":" + port
		}
		start := time.Now()
		conn, err := net.DialTimeout("tcp", target, 3*time.Second)
		if err != nil {
			latencyStr.Set("超时")
		} else {
			conn.Close()
			latencyStr.Set(fmt.Sprintf("%dms", time.Since(start).Milliseconds()))
		}
		time.Sleep(5 * time.Second)
	}
}

func fmtBytes(b uint64) string {
	if b < 1024 {
		return fmt.Sprintf("%d B", b)
	}
	if b < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(b)/1024)
	}
	if b < 1024*1024*1024 {
		return fmt.Sprintf("%.2f MB", float64(b)/1024/1024)
	}
	return fmt.Sprintf("%.2f GB", float64(b)/1024/1024/1024)
}

// ======================== 配置管理 ========================

func loadConfig() AppConfig {
	var c AppConfig
	f, err := os.Open("config.json")
	if err != nil {
		return c
	}
	defer f.Close()
	json.NewDecoder(f).Decode(&c)
	return c
}

func saveConfig(c AppConfig) {
	f, _ := os.Create("config.json")
	e := json.NewEncoder(f)
	e.SetIndent("", "  ")
	e.Encode(c)
	f.Close()
}

func getProfileIndex(c *AppConfig, id string) int {
	for i, s := range c.Servers {
		if s.ID == id {
			return i
		}
	}
	return -1
}

func getCurrentProfileName(c *AppConfig) string {
	i := getProfileIndex(c, c.CurrentServerID)
	if i != -1 {
		return c.Servers[i].Name
	}
	return "未选择"
}

func initDefaultRules(cfg *AppConfig) {
	if len(cfg.BypassDomains) == 0 {
		cfg.BypassDomains = []string{".cn", ".top", ".local", "baidu.com", "qq.com", "163.com", "taobao.com", "jd.com"}
	}
	if len(cfg.BypassKeywords) == 0 {
		cfg.BypassKeywords = []string{"cn", "baidu", "tencent", "alibaba", "360", "bilibili"}
	}
}

// ======================== 分流规则 ========================

func shouldBypass(host string) bool {
	if activeConfig.RoutingMode == "none" {
		return true
	}
	if activeConfig.RoutingMode == "global" {
		return false
	}

	domain := strings.ToLower(host)
	if h, _, err := net.SplitHostPort(domain); err == nil {
		domain = h
	}

	for _, suffix := range globalRules.BypassDomains {
		if strings.HasSuffix(domain, suffix) {
			return true
		}
	}

	for _, kw := range globalRules.BypassKeywords {
		if strings.Contains(domain, kw) {
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
		return true
	}

	return false
}

func isChinaIP(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}

	v := binary.BigEndian.Uint32(ip4)
	chinaIPRangesMu.RLock()
	defer chinaIPRangesMu.RUnlock()

	l, r := 0, len(chinaIPRanges)
	for l < r {
		m := (l + r) / 2
		rg := chinaIPRanges[m]
		if v < rg.start {
			r = m
		} else if v > rg.end {
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
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Get("https://raw.githubusercontent.com/mayaxcn/china-ip-list/refs/heads/master/chn_ip.txt")
		if err == nil {
			defer resp.Body.Close()
			content, _ := io.ReadAll(resp.Body)
			if len(content) > 0 {
				os.WriteFile(path, content, 0644)
			}
		}
	}

	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	var list []ipRange
	scan := bufio.NewScanner(f)
	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		p := strings.Fields(line)
		if len(p) < 2 {
			continue
		}
		s, e := net.ParseIP(p[0]), net.ParseIP(p[1])
		if s != nil && e != nil {
			s4, e4 := s.To4(), e.To4()
			if s4 != nil && e4 != nil {
				list = append(list, ipRange{binary.BigEndian.Uint32(s4), binary.BigEndian.Uint32(e4)})
			}
		}
	}

	chinaIPRangesMu.Lock()
	chinaIPRanges = list
	chinaIPRangesMu.Unlock()
}

// ======================== 日志和系统代理 ========================

func guiLog(f string, args ...any) {
	s := fmt.Sprintf("[%s] %s\n", time.Now().Format("15:04:05"), fmt.Sprintf(f, args...))
	current, _ := logData.Get()
	
	// ✅ 限制日志长度，保留最近的 10000 字符
	if len(current) > 10000 {
		lines := strings.Split(current, "\n")
		if len(lines) > 100 {
			current = strings.Join(lines[len(lines)-100:], "\n")
		}
	}
	
	logData.Set(current + s)
}


func setSystemProxy(enable bool, listen, mode string) bool {
	_, port, _ := net.SplitHostPort(listen)
	if port == "" {
		return false
	}
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
