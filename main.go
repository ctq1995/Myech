package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"image/color"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"syscall"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/gorilla/websocket"
	"golang.org/x/sys/windows/registry"
)

// ==================== 全局变量 ====================

var (
	listenAddr  string
	serverAddr  string
	serverIP    string
	token       string
	dnsServer   string
	echDomain   string
	routingMode string
	autoProxy   bool

	echListMu sync.RWMutex
	echList   []byte

	chinaIPRangesMu sync.RWMutex
	chinaIPRanges   []ipRange

	chinaIPV6RangesMu sync.RWMutex
	chinaIPV6Ranges   []ipRangeV6

	totalUpload   atomic.Uint64
	totalDownload atomic.Uint64
	activeConns   atomic.Int64
	isRunning     atomic.Bool
	proxyListener net.Listener
	statusText    = binding.NewString()
	uploadSpeed   = binding.NewString()
	downloadSpeed = binding.NewString()
	logTextWidget *widget.Entry
	wininet            = syscall.NewLazyDLL("wininet.dll")
	internetSetOptionW = wininet.NewProc("InternetSetOptionW")

	// 优化组件
	wsPool      *WSConnPool
	connLimiter *ConnectionLimiter
	dnsCache    *DNSCache
	asyncLog    *AsyncLogWriter
)

// ==================== 缓冲区池 ====================

var (
	smallBufPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 4*1024) // 4KB
			return &buf
		},
	}
	largeBufPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 32*1024) // 32KB
			return &buf
		},
	}
)

func getBuffer(large bool) *[]byte {
	if large {
		return largeBufPool.Get().(*[]byte)
	}
	return smallBufPool.Get().(*[]byte)
}

func putBuffer(buf *[]byte, large bool) {
	if buf == nil {
		return
	}
	if large {
		largeBufPool.Put(buf)
	} else {
		smallBufPool.Put(buf)
	}
}

// ==================== WebSocket 连接池 ====================

type WSConnPool struct {
	mu       sync.Mutex
	conns    chan *websocket.Conn
	maxSize  int
	minSize  int
	closed   bool
}

func newWSConnPool(minSize, maxSize int) *WSConnPool {
	return &WSConnPool{
		conns:   make(chan *websocket.Conn, maxSize),
		maxSize: maxSize,
		minSize: minSize,
	}
}

func (p *WSConnPool) WarmUp() {
	for i := 0; i < p.minSize; i++ {
		go func() {
			if conn, err := dialWebSocketWithECHInternal(1); err == nil {
				p.Put(conn)
			}
		}()
	}
}

func (p *WSConnPool) Get() (*websocket.Conn, error) {
	// 优先从池中获取
	select {
	case conn := <-p.conns:
		if conn != nil {
			// 检查连接是否有效
			conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
			if err := conn.WriteMessage(websocket.PingMessage, nil); err == nil {
				conn.SetWriteDeadline(time.Time{})
				return conn, nil
			}
			conn.Close()
		}
	default:
	}
	// 创建新连接
	return dialWebSocketWithECHInternal(2)
}

func (p *WSConnPool) Put(conn *websocket.Conn) {
	if conn == nil {
		return
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		conn.Close()
		return
	}
	p.mu.Unlock()

	select {
	case p.conns <- conn:
	default:
		conn.Close()
	}
}

func (p *WSConnPool) Close() {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()

	close(p.conns)
	for conn := range p.conns {
		if conn != nil {
			conn.Close()
		}
	}
}

// ==================== 连接数限制器 ====================

type ConnectionLimiter struct {
	sem     chan struct{}
	maxConn int
}

func newConnectionLimiter(maxConns int) *ConnectionLimiter {
	return &ConnectionLimiter{
		sem:     make(chan struct{}, maxConns),
		maxConn: maxConns,
	}
}

func (l *ConnectionLimiter) Acquire() bool {
	select {
	case l.sem <- struct{}{}:
		activeConns.Add(1)
		return true
	default:
		return false
	}
}

func (l *ConnectionLimiter) Release() {
	select {
	case <-l.sem:
		activeConns.Add(-1)
	default:
	}
}

// ==================== DNS 缓存 ====================

type DNSCache struct {
	mu      sync.RWMutex
	entries map[string]*dnsCacheEntry
	maxSize int
}

type dnsCacheEntry struct {
	ips       []net.IP
	isChinaIP bool
	expiresAt time.Time
}

func newDNSCache(maxSize int) *DNSCache {
	return &DNSCache{
		entries: make(map[string]*dnsCacheEntry),
		maxSize: maxSize,
	}
}

func (c *DNSCache) Get(host string) ([]net.IP, bool, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[host]
	if !ok || time.Now().After(entry.expiresAt) {
		return nil, false, false
	}
	return entry.ips, entry.isChinaIP, true
}

func (c *DNSCache) Set(host string, ips []net.IP, isChinaIP bool, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 清理过期条目
	if len(c.entries) >= c.maxSize {
		now := time.Now()
		for k, v := range c.entries {
			if now.After(v.expiresAt) {
				delete(c.entries, k)
			}
		}
		// 如果还是满的，删除一半
		if len(c.entries) >= c.maxSize {
			count := 0
			for k := range c.entries {
				delete(c.entries, k)
				count++
				if count >= c.maxSize/2 {
					break
				}
			}
		}
	}

	c.entries[host] = &dnsCacheEntry{
		ips:       ips,
		isChinaIP: isChinaIP,
		expiresAt: time.Now().Add(ttl),
	}
}

func (c *DNSCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*dnsCacheEntry)
}

// ==================== 异步日志 ====================

type AsyncLogWriter struct {
	ch       chan string
	done     chan struct{}
	logs     []string
	mu       sync.Mutex
	maxLogs  int
	updating atomic.Bool
}

func newAsyncLogWriter(maxLogs int) *AsyncLogWriter {
	w := &AsyncLogWriter{
		ch:      make(chan string, 500),
		done:    make(chan struct{}),
		logs:    make([]string, 0, maxLogs),
		maxLogs: maxLogs,
	}
	go w.run()
	return w
}

func (w *AsyncLogWriter) run() {
	ticker := time.NewTicker(150 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case msg := <-w.ch:
			w.mu.Lock()
			w.logs = append(w.logs, msg)
			if len(w.logs) > w.maxLogs {
				w.logs = w.logs[len(w.logs)-w.maxLogs:]
			}
			w.mu.Unlock()

		case <-ticker.C:
			w.flush()

		case <-w.done:
			// 清空剩余日志
			for {
				select {
				case msg := <-w.ch:
					w.mu.Lock()
					w.logs = append(w.logs, msg)
					w.mu.Unlock()
				default:
					w.flush()
					return
				}
			}
		}
	}
}

func (w *AsyncLogWriter) flush() {
	if w.updating.Load() {
		return
	}

	w.mu.Lock()
	if len(w.logs) == 0 {
		w.mu.Unlock()
		return
	}
	logText := strings.Join(w.logs, "\n")
	w.mu.Unlock()

	if logTextWidget != nil {
		w.updating.Store(true)
		fyne.Do(func() {
			logTextWidget.SetText(logText)
			logTextWidget.CursorRow = len(w.logs)
			w.updating.Store(false)
		})
	}
}

func (w *AsyncLogWriter) Write(p []byte) (n int, err error) {
	msg := strings.TrimSpace(string(p))
	if msg == "" {
		return len(p), nil
	}

	// 同时输出到控制台
	os.Stdout.Write(p)

	timeStr := time.Now().Format("15:04:05")
	logLine := fmt.Sprintf("[%s] %s", timeStr, msg)

	select {
	case w.ch <- logLine:
	default:
		// 通道满了，丢弃
	}

	return len(p), nil
}

func (w *AsyncLogWriter) Close() {
	close(w.done)
}

// ==================== 自定义主题 ====================

type customTheme struct{}

func (t *customTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNameBackground:
		return color.NRGBA{R: 30, G: 30, B: 35, A: 255}
	case theme.ColorNameButton:
		return color.NRGBA{R: 55, G: 55, B: 65, A: 255}
	case theme.ColorNameDisabledButton:
		return color.NRGBA{R: 45, G: 45, B: 50, A: 255}
	case theme.ColorNameDisabled:
		return color.NRGBA{R: 100, G: 100, B: 100, A: 255}
	case theme.ColorNameForeground:
		return color.NRGBA{R: 220, G: 220, B: 225, A: 255}
	case theme.ColorNameHover:
		return color.NRGBA{R: 70, G: 70, B: 80, A: 255}
	case theme.ColorNameInputBackground:
		return color.NRGBA{R: 40, G: 40, B: 48, A: 255}
	case theme.ColorNameInputBorder:
		return color.NRGBA{R: 80, G: 80, B: 90, A: 255}
	case theme.ColorNamePlaceHolder:
		return color.NRGBA{R: 120, G: 120, B: 130, A: 255}
	case theme.ColorNamePrimary:
		return color.NRGBA{R: 65, G: 150, B: 255, A: 255}
	case theme.ColorNameScrollBar:
		return color.NRGBA{R: 80, G: 80, B: 90, A: 255}
	case theme.ColorNameSeparator:
		return color.NRGBA{R: 60, G: 60, B: 70, A: 255}
	case theme.ColorNameShadow:
		return color.NRGBA{R: 0, G: 0, B: 0, A: 100}
	case theme.ColorNameSuccess:
		return color.NRGBA{R: 76, G: 175, B: 80, A: 255}
	case theme.ColorNameWarning:
		return color.NRGBA{R: 255, G: 152, B: 0, A: 255}
	case theme.ColorNameError:
		return color.NRGBA{R: 244, G: 67, B: 54, A: 255}
	default:
		return theme.DefaultTheme().Color(name, variant)
	}
}

func (t *customTheme) Font(style fyne.TextStyle) fyne.Resource {
	return theme.DefaultTheme().Font(style)
}

func (t *customTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(name)
}

func (t *customTheme) Size(name fyne.ThemeSizeName) float32 {
	switch name {
	case theme.SizeNamePadding:
		return 6
	case theme.SizeNameInlineIcon:
		return 20
	case theme.SizeNameScrollBar:
		return 12
	case theme.SizeNameText:
		return 14
	default:
		return theme.DefaultTheme().Size(name)
	}
}

// ==================== IP 范围结构 ====================

type ipRange struct {
	start uint32
	end   uint32
}

type ipRangeV6 struct {
	start [16]byte
	end   [16]byte
}

// ==================== 流量统计连接包装 ====================

type TrafficConn struct {
	net.Conn
}

func (c *TrafficConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if n > 0 {
		// 从客户端读取 = 客户端上传的数据
		totalUpload.Add(uint64(n))
	}
	return
}

func (c *TrafficConn) Write(b []byte) (n int, err error) {
	n, err = c.Conn.Write(b)
	if n > 0 {
		// 写入到客户端 = 客户端下载的数据
		totalDownload.Add(uint64(n))
	}
	return
}


// ==================== 工具函数 ====================

func formatSize(s float64) string {
	units := []string{"B", "KB", "MB", "GB", "TB"}
	i := 0
	for s >= 1024 && i < len(units)-1 {
		s /= 1024
		i++
	}
	return fmt.Sprintf("%.1f %s", s, units[i])
}

func formatSpeed(s float64) string {
	units := []string{"B/s", "KB/s", "MB/s", "GB/s"}
	i := 0
	for s >= 1024 && i < len(units)-1 {
		s /= 1024
		i++
	}
	return fmt.Sprintf("%.1f %s", s, units[i])
}

func isNormalCloseError(err error) bool {
	if err == nil {
		return false
	}
	if err == io.EOF {
		return true
	}
	errStr := err.Error()
	return strings.Contains(errStr, "use of closed network connection") ||
		strings.Contains(errStr, "broken pipe") ||
		strings.Contains(errStr, "connection reset by peer") ||
		strings.Contains(errStr, "normal closure") ||
		strings.Contains(errStr, "An existing connection was forcibly closed")
}

// ==================== 系统代理设置 ====================

func setSystemProxy(enable bool, proxyAddr string) error {
	if runtime.GOOS != "windows" {
		log.Printf("[系统代理] 当前系统 %s 暂不支持自动设置", runtime.GOOS)
		return nil
	}
	key, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Internet Settings`,
		registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return fmt.Errorf("打开注册表失败: %w", err)
	}
	defer key.Close()
	if enable {
		if err := key.SetDWordValue("ProxyEnable", 1); err != nil {
			return fmt.Errorf("设置 ProxyEnable 失败: %w", err)
		}
		if err := key.SetStringValue("ProxyServer", proxyAddr); err != nil {
			return fmt.Errorf("设置 ProxyServer 失败: %w", err)
		}
		bypass := "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;<local>"
		if err := key.SetStringValue("ProxyOverride", bypass); err != nil {
			return fmt.Errorf("设置 ProxyOverride 失败: %w", err)
		}
		log.Printf("[系统代理] 已启用: %s", proxyAddr)
	} else {
		if err := key.SetDWordValue("ProxyEnable", 0); err != nil {
			return fmt.Errorf("禁用代理失败: %w", err)
		}
		log.Printf("[系统代理] 已禁用")
	}
	// 使用 Windows API 刷新（无窗口闪烁）
	notifyProxyChange()
	return nil
}
func notifyProxyChange() {
	if runtime.GOOS != "windows" {
		return
	}
	internetSetOptionW.Call(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
	internetSetOptionW.Call(0, INTERNET_OPTION_REFRESH, 0, 0)
}


// ==================== GUI 组件创建 ====================

func createCard(title string, content fyne.CanvasObject) *fyne.Container {
	titleLabel := widget.NewLabel(title)
	titleLabel.TextStyle = fyne.TextStyle{Bold: true}

	titleBg := canvas.NewRectangle(color.NRGBA{R: 45, G: 45, B: 55, A: 255})
	titleBg.SetMinSize(fyne.NewSize(0, 32))

	titleContainer := container.NewStack(titleBg, container.NewPadded(titleLabel))

	contentBg := canvas.NewRectangle(color.NRGBA{R: 38, G: 38, B: 45, A: 255})
	contentContainer := container.NewStack(contentBg, content)

	return container.NewBorder(titleContainer, nil, nil, nil, contentContainer)
}

func createStatusIndicator(running bool) *canvas.Circle {
	circle := canvas.NewCircle(color.NRGBA{R: 100, G: 100, B: 100, A: 255})
	if running {
		circle.FillColor = color.NRGBA{R: 76, G: 175, B: 80, A: 255}
	} else {
		circle.FillColor = color.NRGBA{R: 244, G: 67, B: 54, A: 255}
	}
	circle.Resize(fyne.NewSize(12, 12))
	return circle
}

// ==================== 主函数 ====================

func main() {
	// 设置 CPU 核心数
	runtime.GOMAXPROCS(runtime.NumCPU())

	// 初始化异步日志
	asyncLog = newAsyncLogWriter(100)
	log.SetOutput(asyncLog)
	log.SetFlags(0)

	// 初始化连接限制器
	connLimiter = newConnectionLimiter(500)

	// 初始化 DNS 缓存
	dnsCache = newDNSCache(1000)

	myApp := app.NewWithID("com.echproxy.gui")
	myApp.Settings().SetTheme(&customTheme{})

	myWindow := myApp.NewWindow("ECH Proxy Client")
	myWindow.Resize(fyne.NewSize(1000, 700))
	myWindow.CenterOnScreen()

	// 加载偏好设置
	prefs := myApp.Preferences()
	listenAddr = prefs.StringWithFallback("listenAddr", "127.0.0.1:30000")
	serverAddr = prefs.StringWithFallback("serverAddr", "")
	serverIP = prefs.StringWithFallback("serverIP", "")
	token = prefs.StringWithFallback("token", "")
	dnsServer = prefs.StringWithFallback("dnsServer", "dns.alidns.com/dns-query")
	echDomain = prefs.StringWithFallback("echDomain", "cloudflare-ech.com")
	routingMode = prefs.StringWithFallback("routingMode", "global")
	autoProxy = prefs.BoolWithFallback("autoProxy", true)

	// 初始化绑定值
	statusText.Set("已停止")
	uploadSpeed.Set("0 B/s")
	downloadSpeed.Set("0 B/s")

	uploadTotal := binding.NewString()
	uploadTotal.Set("0 B")
	downloadTotal := binding.NewString()
	downloadTotal.Set("0 B")
	connCount := binding.NewString()
	connCount.Set("0")

	// ========== 状态面板 ==========
	statusIndicator := createStatusIndicator(false)
	statusLabel := widget.NewLabelWithData(statusText)
	statusLabel.TextStyle = fyne.TextStyle{Bold: true}

	statusRow := container.NewHBox(
		statusIndicator,
		widget.NewLabel("状态:"),
		statusLabel,
	)

	uploadSpeedLabel := widget.NewLabelWithData(uploadSpeed)
	downloadSpeedLabel := widget.NewLabelWithData(downloadSpeed)
	uploadTotalLabel := widget.NewLabelWithData(uploadTotal)
	downloadTotalLabel := widget.NewLabelWithData(downloadTotal)
	connCountLabel := widget.NewLabelWithData(connCount)

	createFixedLabel := func(text string, width float32) *fyne.Container {
		lbl := widget.NewLabel(text)
		return container.NewGridWrap(fyne.NewSize(width, 25), lbl)
	}

	createFixedValueLabel := func(label *widget.Label, width float32) *fyne.Container {
		return container.NewGridWrap(fyne.NewSize(width, 25), label)
	}

	speedRow := container.NewHBox(
		widget.NewIcon(theme.UploadIcon()),
		createFixedLabel("上传:", 45),
		createFixedValueLabel(uploadSpeedLabel, 90),
		widget.NewSeparator(),
		widget.NewIcon(theme.DownloadIcon()),
		createFixedLabel("下载:", 45),
		createFixedValueLabel(downloadSpeedLabel, 90),
	)

	trafficRow := container.NewHBox(
		createFixedLabel("↑ 已上传:", 75),
		createFixedValueLabel(uploadTotalLabel, 90),
		widget.NewSeparator(),
		createFixedLabel("↓ 已下载:", 75),
		createFixedValueLabel(downloadTotalLabel, 90),
	)

	connRow := container.NewHBox(
		createFixedLabel("活动连接:", 75),
		createFixedValueLabel(connCountLabel, 60),
	)

	statsContent := container.NewVBox(
		container.NewPadded(statusRow),
		widget.NewSeparator(),
		container.NewPadded(speedRow),
		widget.NewSeparator(),
		container.NewPadded(trafficRow),
		widget.NewSeparator(),
		container.NewPadded(connRow),
	)
	statsCard := createCard("📊 运行状态", statsContent)

	// ========== 配置面板 ==========
	labelWidth := float32(90)
	entryWidth := float32(260)

	createFormRow := func(labelText string, w fyne.CanvasObject) *fyne.Container {
		lbl := widget.NewLabel(labelText)
		lbl.TextStyle = fyne.TextStyle{Bold: true}
		labelBox := container.NewGridWrap(fyne.NewSize(labelWidth, 36), lbl)
		entryBox := container.NewGridWrap(fyne.NewSize(entryWidth, 36), w)
		return container.NewHBox(labelBox, entryBox)
	}

	listenEntry := widget.NewEntry()
	listenEntry.SetText(listenAddr)
	listenEntry.SetPlaceHolder("127.0.0.1:30000")

	serverEntry := widget.NewEntry()
	serverEntry.SetText(serverAddr)
	serverEntry.SetPlaceHolder("your-worker.workers.dev:443")

	tokenEntry := widget.NewPasswordEntry()
	tokenEntry.SetText(token)
	tokenEntry.SetPlaceHolder("可选的认证令牌")

	serverIPEntry := widget.NewEntry()
	serverIPEntry.SetText(serverIP)
	serverIPEntry.SetPlaceHolder("可选，指定服务器IP")

	dnsEntry := widget.NewEntry()
	dnsEntry.SetText(dnsServer)

	echEntry := widget.NewEntry()
	echEntry.SetText(echDomain)

	routingSelect := widget.NewSelect([]string{"global", "bypass_cn", "none"}, func(s string) {
		routingMode = s
	})
	routingSelect.PlaceHolder = "选择分流模式"

	autoProxyCheck := widget.NewCheck("启动时自动设置系统代理", func(checked bool) {
		autoProxy = checked
		prefs.SetBool("autoProxy", autoProxy)
	})
	autoProxyCheck.SetChecked(autoProxy)

	configContent := container.NewVBox(
		createFormRow("监听地址", listenEntry),
		createFormRow("服务器地址", serverEntry),
		createFormRow("认证令牌", tokenEntry),
		createFormRow("服务器 IP", serverIPEntry),
		createFormRow("分流模式", routingSelect),
		createFormRow("DoH 服务器", dnsEntry),
		createFormRow("ECH 域名", echEntry),
		widget.NewSeparator(),
		container.NewPadded(autoProxyCheck),
	)
	configCard := createCard("⚙️ 代理配置", configContent)

	// ========== 控制按钮 ==========
	var startBtn *widget.Button

	enableInputs := func() {
		listenEntry.Enable()
		serverEntry.Enable()
		tokenEntry.Enable()
		serverIPEntry.Enable()
		dnsEntry.Enable()
		echEntry.Enable()
		routingSelect.Enable()
		autoProxyCheck.Enable()
	}

	disableInputs := func() {
		listenEntry.Disable()
		serverEntry.Disable()
		tokenEntry.Disable()
		serverIPEntry.Disable()
		dnsEntry.Disable()
		echEntry.Disable()
		routingSelect.Disable()
		autoProxyCheck.Disable()
	}

	startBtn = widget.NewButton("启动代理", func() {
		if isRunning.Load() {
			// 停止代理
			if proxyListener != nil {
				proxyListener.Close()
			}
			if wsPool != nil {
				wsPool.Close()
				wsPool = nil
			}
			isRunning.Store(false)

			if autoProxy {
				setSystemProxy(false, "")
			}

			statusText.Set("已停止")
			statusIndicator.FillColor = color.NRGBA{R: 244, G: 67, B: 54, A: 255}
			statusIndicator.Refresh()
			startBtn.SetText("启动代理")
			startBtn.Importance = widget.HighImportance
			enableInputs()
		} else {
			// 启动代理
			listenAddr = listenEntry.Text
			serverAddr = serverEntry.Text
			serverIP = serverIPEntry.Text
			token = tokenEntry.Text
			dnsServer = dnsEntry.Text
			echDomain = echEntry.Text

			if serverAddr == "" {
				dialog.ShowError(errors.New("请输入服务器地址"), myWindow)
				return
			}

			prefs.SetString("listenAddr", listenAddr)
			prefs.SetString("serverAddr", serverAddr)
			prefs.SetString("serverIP", serverIP)
			prefs.SetString("token", token)
			prefs.SetString("dnsServer", dnsServer)
			prefs.SetString("echDomain", echDomain)
			prefs.SetString("routingMode", routingMode)

			disableInputs()
			startBtn.SetText("正在启动...")
			startBtn.Disable()
			statusText.Set("正在启动...")

			go func() {
				log.Printf("[启动] 正在获取 ECH 配置...")
				if err := prepareECH(); err != nil {
					log.Printf("[错误] 获取 ECH 失败: %v", err)
					fyne.Do(func() {
						statusText.Set("启动失败")
						startBtn.SetText("启动代理")
						startBtn.Importance = widget.HighImportance
						startBtn.Enable()
						enableInputs()
					})
					return
				}

				// 初始化连接池
				wsPool = newWSConnPool(2, 10)
				wsPool.WarmUp()

				if routingMode == "bypass_cn" {
					log.Printf("[启动] 加载分流规则...")
					loadChinaIPList()
					loadChinaIPV6List()
				}

				if err := startProxyListener(); err != nil {
					log.Printf("[错误] 监听失败: %v", err)
					fyne.Do(func() {
						statusText.Set("启动失败")
						startBtn.SetText("启动代理")
						startBtn.Importance = widget.HighImportance
						startBtn.Enable()
						enableInputs()
					})
					return
				}

				if autoProxy {
					if err := setSystemProxy(true, listenAddr); err != nil {
						log.Printf("[警告] 设置系统代理失败: %v", err)
					}
				}

				isRunning.Store(true)
				fyne.Do(func() {
					statusText.Set(fmt.Sprintf("运行中 - %s", listenAddr))
					statusIndicator.FillColor = color.NRGBA{R: 76, G: 175, B: 80, A: 255}
					statusIndicator.Refresh()
					startBtn.SetText("停止代理")
					startBtn.Importance = widget.DangerImportance
					startBtn.Enable()
				})
			}()
		}
	})
	startBtn.Importance = widget.HighImportance

	// 按钮固定大小
	buttonBox := container.NewGridWrap(fyne.NewSize(360, 45), startBtn)
	buttonContainer := container.NewCenter(buttonBox)

	// ========== 左侧面板 ==========
	leftPanel := container.NewVBox(
		statsCard,
		configCard,
		buttonContainer,
	)

	// 使用 Padded 包装，不设置固定高度
	leftPanelWithPadding := container.NewPadded(leftPanel)

	// ========== 日志面板 ==========
	logTextWidget = widget.NewMultiLineEntry()
	logTextWidget.Wrapping = fyne.TextWrapWord
	logTextWidget.TextStyle = fyne.TextStyle{Monospace: true}
	logTextWidget.Disable()

	logScroll := container.NewVScroll(logTextWidget)
	logScroll.SetMinSize(fyne.NewSize(400, 600))
	logCard := createCard("📝 运行日志", logScroll)

	// ========== 主布局 ==========
	// 使用 HSplit 分割左右两部分
	split := container.NewHSplit(leftPanelWithPadding, logCard)
	split.SetOffset(0.42) // 左侧占 42%

	// 底部状态栏
	versionLabel := widget.NewLabel("ECH Proxy v1.0")
	versionLabel.TextStyle = fyne.TextStyle{Italic: true}

	bottomBar := container.NewBorder(
		widget.NewSeparator(),
		nil, nil, nil,
		container.NewPadded(versionLabel),
	)

	// 最终布局
	content := container.NewBorder(nil, bottomBar, nil, nil, split)
	myWindow.SetContent(content)

	// 延迟设置 Select 选中值
	routingSelect.SetSelected(routingMode)

	// 流量监控定时器
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		var lastUp, lastDown uint64
		for range ticker.C {
			currUp := totalUpload.Load()
			currDown := totalDownload.Load()

			diffUp := float64(currUp - lastUp)
			diffDown := float64(currDown - lastDown)

			lastUp = currUp
			lastDown = currDown

			upSpd := formatSpeed(diffUp)
			downSpd := formatSpeed(diffDown)
			upTotal := formatSize(float64(currUp))
			downTotal := formatSize(float64(currDown))
			conns := fmt.Sprintf("%d", activeConns.Load())

			fyne.Do(func() {
				uploadSpeed.Set(upSpd)
				downloadSpeed.Set(downSpd)
				uploadTotal.Set(upTotal)
				downloadTotal.Set(downTotal)
				connCount.Set(conns)
			})
		}
	}()

	// 窗口关闭清理
	myWindow.SetOnClosed(func() {
		if isRunning.Load() {
			if proxyListener != nil {
				proxyListener.Close()
			}
			if wsPool != nil {
				wsPool.Close()
			}
			if autoProxy {
				setSystemProxy(false, "")
			}
		}
		if asyncLog != nil {
			asyncLog.Close()
		}
	})

	// 延迟刷新
	go func() {
		time.Sleep(200 * time.Millisecond)
		fyne.Do(func() {
			myWindow.Content().Refresh()
		})
	}()

	myWindow.ShowAndRun()
}


// ==================== 代理服务器 ====================

func startProxyListener() error {
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}
	proxyListener = listener
	log.Printf("[代理] 服务器启动: %s", listenAddr)
	log.Printf("[代理] 后端: %s", serverAddr)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				if isRunning.Load() {
					if !strings.Contains(err.Error(), "use of closed") {
						log.Printf("[代理] Accept 错误: %v", err)
					}
				}
				return
			}

			// 连接数限制
			if !connLimiter.Acquire() {
				log.Printf("[限制] 连接数已满，拒绝: %s", conn.RemoteAddr())
				conn.Close()
				continue
			}

			wrappedConn := &TrafficConn{Conn: conn}
			go func() {
				defer connLimiter.Release()
				handleConnection(wrappedConn)
			}()
		}
	}()
	return nil
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	clientAddr := conn.RemoteAddr().String()

	conn.SetDeadline(time.Now().Add(30 * time.Second))

	buf := make([]byte, 1)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return
	}

	firstByte := buf[0]
	switch firstByte {
	case 0x05:
		handleSOCKS5(conn, clientAddr, firstByte)
	case 'C', 'G', 'P', 'H', 'D', 'O', 'T':
		handleHTTP(conn, clientAddr, firstByte)
	default:
		log.Printf("[代理] %s 未知协议: 0x%02x", clientAddr, firstByte)
	}
}

// ==================== SOCKS5 处理 ====================

func handleSOCKS5(conn net.Conn, clientAddr string, firstByte byte) {
	if firstByte != 0x05 {
		return
	}

	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}
	nmethods := buf[0]
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}

	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	buf = make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}

	if buf[0] != 5 {
		return
	}

	command := buf[1]
	atyp := buf[3]

	var host string
	switch atyp {
	case 0x01:
		buf = make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		host = net.IP(buf).String()
	case 0x03:
		buf = make([]byte, 1)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		domainBuf := make([]byte, buf[0])
		if _, err := io.ReadFull(conn, domainBuf); err != nil {
			return
		}
		host = string(domainBuf)
	case 0x04:
		buf = make([]byte, 16)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		host = net.IP(buf).String()
	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}

	buf = make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}
	port := int(buf[0])<<8 | int(buf[1])

	switch command {
	case 0x01:
		var target string
		if atyp == 0x04 {
			target = fmt.Sprintf("[%s]:%d", host, port)
		} else {
			target = fmt.Sprintf("%s:%d", host, port)
		}
		log.Printf("[SOCKS5] %s -> %s", clientAddr, target)
		if err := handleTunnel(conn, target, clientAddr, modeSOCKS5, ""); err != nil {
			if !isNormalCloseError(err) {
				log.Printf("[SOCKS5] %s 失败: %v", clientAddr, err)
			}
		}
	case 0x03:
		handleUDPAssociate(conn, clientAddr)
	default:
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	}
}

func handleUDPAssociate(tcpConn net.Conn, clientAddr string) {
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		tcpConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		tcpConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}

	localAddr := udpConn.LocalAddr().(*net.UDPAddr)
	port := localAddr.Port
	log.Printf("[UDP] %s UDP ASSOCIATE 端口: %d", clientAddr, port)

	response := []byte{0x05, 0x00, 0x00, 0x01}
	response = append(response, 127, 0, 0, 1)
	response = append(response, byte(port>>8), byte(port&0xff))

	if _, err := tcpConn.Write(response); err != nil {
		udpConn.Close()
		return
	}

	stopChan := make(chan struct{})
	go handleUDPRelay(udpConn, clientAddr, stopChan)

	buf := make([]byte, 1)
	tcpConn.Read(buf)
	close(stopChan)
	udpConn.Close()
}

func handleUDPRelay(udpConn *net.UDPConn, clientAddr string, stopChan chan struct{}) {
	buf := getBuffer(true)
	defer putBuffer(buf, true)

	for {
		select {
		case <-stopChan:
			return
		default:
		}

		udpConn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, addr, err := udpConn.ReadFromUDP(*buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return
		}

		if n < 10 {
			continue
		}

		data := (*buf)[:n]
		if data[2] != 0x00 {
			continue
		}

		atyp := data[3]
		var headerLen int
		var dstPort int

		switch atyp {
		case 0x01:
			if n < 10 {
				continue
			}
			dstPort = int(data[8])<<8 | int(data[9])
			headerLen = 10
		case 0x03:
			if n < 5 {
				continue
			}
			domainLen := int(data[4])
			if n < 7+domainLen {
				continue
			}
			dstPort = int(data[5+domainLen])<<8 | int(data[6+domainLen])
			headerLen = 7 + domainLen
		case 0x04:
			if n < 22 {
				continue
			}
			dstPort = int(data[20])<<8 | int(data[21])
			headerLen = 22
		default:
			continue
		}

		udpData := make([]byte, n-headerLen)
		copy(udpData, data[headerLen:])
		header := make([]byte, headerLen)
		copy(header, data[:headerLen])

		if dstPort == 53 {
			go handleDNSQuery(udpConn, addr, udpData, header)
		}
	}
}

func handleDNSQuery(udpConn *net.UDPConn, clientAddr *net.UDPAddr, dnsQuery []byte, socks5Header []byte) {
	dnsResponse, err := queryDoHForProxy(dnsQuery)
	if err != nil {
		log.Printf("[UDP-DNS] DoH 查询失败: %v", err)
		return
	}

	response := make([]byte, 0, len(socks5Header)+len(dnsResponse))
	response = append(response, socks5Header...)
	response = append(response, dnsResponse...)
	udpConn.WriteToUDP(response, clientAddr)
}

// ==================== HTTP 处理 ====================

func handleHTTP(conn net.Conn, clientAddr string, firstByte byte) {
	reader := bufio.NewReader(io.MultiReader(strings.NewReader(string(firstByte)), conn))

	requestLine, err := reader.ReadString('\n')
	if err != nil {
		return
	}

	parts := strings.Fields(requestLine)
	if len(parts) < 3 {
		return
	}

	method := parts[0]
	requestURL := parts[1]
	httpVersion := parts[2]

	headers := make(map[string]string)
	var headerLines []string

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		headerLines = append(headerLines, line)
		if idx := strings.Index(line, ":"); idx > 0 {
			key := strings.TrimSpace(line[:idx])
			value := strings.TrimSpace(line[idx+1:])
			headers[strings.ToLower(key)] = value
		}
	}

	switch method {
	case "CONNECT":
		log.Printf("[HTTPS] %s -> %s", clientAddr, requestURL)
		if err := handleTunnel(conn, requestURL, clientAddr, modeHTTPConnect, ""); err != nil {
			if !isNormalCloseError(err) {
				log.Printf("[HTTPS] %s 失败: %v", clientAddr, err)
			}
		}

	case "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE":
		log.Printf("[HTTP] %s %s -> %s", method, clientAddr, requestURL)

		var target, path string
		if strings.HasPrefix(requestURL, "http://") {
			urlWithoutScheme := strings.TrimPrefix(requestURL, "http://")
			idx := strings.Index(urlWithoutScheme, "/")
			if idx > 0 {
				target = urlWithoutScheme[:idx]
				path = urlWithoutScheme[idx:]
			} else {
				target = urlWithoutScheme
				path = "/"
			}
		} else {
			target = headers["host"]
			path = requestURL
		}

		if target == "" {
			conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
			return
		}

		if !strings.Contains(target, ":") {
			target += ":80"
		}

		var requestBuilder strings.Builder
		requestBuilder.WriteString(fmt.Sprintf("%s %s %s\r\n", method, path, httpVersion))
		for _, line := range headerLines {
			key := strings.Split(line, ":")[0]
			keyLower := strings.ToLower(strings.TrimSpace(key))
			if keyLower != "proxy-connection" && keyLower != "proxy-authorization" {
				requestBuilder.WriteString(line)
				requestBuilder.WriteString("\r\n")
			}
		}
		requestBuilder.WriteString("\r\n")

		if contentLength := headers["content-length"]; contentLength != "" {
			var length int
			fmt.Sscanf(contentLength, "%d", &length)
			if length > 0 && length < 10*1024*1024 {
				body := make([]byte, length)
				if _, err := io.ReadFull(reader, body); err == nil {
					requestBuilder.Write(body)
				}
			}
		}

		firstFrame := requestBuilder.String()
		if err := handleTunnel(conn, target, clientAddr, modeHTTPProxy, firstFrame); err != nil {
			if !isNormalCloseError(err) {
				log.Printf("[HTTP] %s 失败: %v", clientAddr, err)
			}
		}

	default:
		conn.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\n\r\n"))
	}
}

// ==================== 隧道处理 ====================

const (
	modeSOCKS5      = 1
	modeHTTPConnect = 2
	modeHTTPProxy   = 3
	INTERNET_OPTION_SETTINGS_CHANGED = 39
	INTERNET_OPTION_REFRESH          = 37
)

func handleTunnel(conn net.Conn, target, clientAddr string, mode int, firstFrame string) error {
	targetHost, _, err := net.SplitHostPort(target)
	if err != nil {
		targetHost = target
	}

	if shouldBypassProxy(targetHost) {
		log.Printf("[直连] %s -> %s", clientAddr, target)
		return handleDirectConnection(conn, target, clientAddr, mode, firstFrame)
	}

	log.Printf("[代理] %s -> %s", clientAddr, target)

	// 从连接池获取或创建新连接
	var wsConn *websocket.Conn
	if wsPool != nil {
		wsConn, err = wsPool.Get()
	} else {
		wsConn, err = dialWebSocketWithECHInternal(2)
	}
	if err != nil {
		sendErrorResponse(conn, mode)
		return err
	}

	var mu sync.Mutex
	stopPing := make(chan bool)

	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				mu.Lock()
				wsConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				wsConn.WriteMessage(websocket.PingMessage, nil)
				wsConn.SetWriteDeadline(time.Time{})
				mu.Unlock()
			case <-stopPing:
				return
			}
		}
	}()

	defer func() {
		close(stopPing)
		// 不放回连接池，因为连接已经用于特定目标
		wsConn.Close()
	}()

	conn.SetDeadline(time.Time{})

	if firstFrame == "" && mode == modeSOCKS5 {
		conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		buffer := getBuffer(true)
		n, _ := conn.Read(*buffer)
		conn.SetReadDeadline(time.Time{})
		if n > 0 {
			firstFrame = string((*buffer)[:n])
		}
		putBuffer(buffer, true)
	}

	connectMsg := fmt.Sprintf("CONNECT:%s|%s", target, firstFrame)
	mu.Lock()
	err = wsConn.WriteMessage(websocket.TextMessage, []byte(connectMsg))
	mu.Unlock()
	if err != nil {
		sendErrorResponse(conn, mode)
		return err
	}

	_, msg, err := wsConn.ReadMessage()
	if err != nil {
		sendErrorResponse(conn, mode)
		return err
	}

	response := string(msg)
	if strings.HasPrefix(response, "ERROR:") {
		sendErrorResponse(conn, mode)
		return errors.New(response)
	}

	if response != "CONNECTED" {
		sendErrorResponse(conn, mode)
		return fmt.Errorf("意外响应: %s", response)
	}

	if err := sendSuccessResponse(conn, mode); err != nil {
		return err
	}

	done := make(chan bool, 2)

	// 客户端 -> WebSocket
	go func() {
		buf := getBuffer(true)
		defer putBuffer(buf, true)

		for {
			n, err := conn.Read(*buf)
			if err != nil {
				mu.Lock()
				wsConn.WriteMessage(websocket.TextMessage, []byte("CLOSE"))
				mu.Unlock()
				done <- true
				return
			}
			mu.Lock()
			err = wsConn.WriteMessage(websocket.BinaryMessage, (*buf)[:n])
			mu.Unlock()
			if err != nil {
				done <- true
				return
			}
		}
	}()

	// WebSocket -> 客户端
	go func() {
		for {
			mt, msg, err := wsConn.ReadMessage()
			if err != nil {
				done <- true
				return
			}
			if mt == websocket.TextMessage && string(msg) == "CLOSE" {
				done <- true
				return
			}
			if _, err := conn.Write(msg); err != nil {
				done <- true
				return
			}
		}
	}()

	<-done
	return nil
}

func handleDirectConnection(conn net.Conn, target, clientAddr string, mode int, firstFrame string) error {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		host = target
		if mode == modeHTTPConnect || mode == modeHTTPProxy {
			port = "443"
		} else {
			port = "80"
		}
		target = net.JoinHostPort(host, port)
	}

	targetConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		sendErrorResponse(conn, mode)
		return fmt.Errorf("直连失败: %w", err)
	}
	defer targetConn.Close()

	if err := sendSuccessResponse(conn, mode); err != nil {
		return err
	}

	if firstFrame != "" {
		if _, err := targetConn.Write([]byte(firstFrame)); err != nil {
			return err
		}
	}

	done := make(chan error, 2)

	go func() {
		buf := getBuffer(true)
		defer putBuffer(buf, true)
		_, err := io.CopyBuffer(targetConn, conn, *buf)
		done <- err
	}()

	go func() {
		buf := getBuffer(true)
		defer putBuffer(buf, true)
		_, err := io.CopyBuffer(conn, targetConn, *buf)
		done <- err
	}()

	<-done
	return nil
}

func sendErrorResponse(conn net.Conn, mode int) {
	switch mode {
	case modeSOCKS5:
		conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	case modeHTTPConnect, modeHTTPProxy:
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
	}
}

func sendSuccessResponse(conn net.Conn, mode int) error {
	switch mode {
	case modeSOCKS5:
		_, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return err
	case modeHTTPConnect:
		_, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		return err
	case modeHTTPProxy:
		return nil
	}
	return nil
}

// ==================== 分流判断 ====================

func shouldBypassProxy(targetHost string) bool {
	if routingMode == "none" {
		return true
	}
	if routingMode == "global" {
		return false
	}
	if routingMode != "bypass_cn" {
		return false
	}

	// 检查是否为 IP
	if ip := net.ParseIP(targetHost); ip != nil {
		return isChinaIP(targetHost)
	}

	// 检查 DNS 缓存
	if dnsCache != nil {
		if _, isCN, ok := dnsCache.Get(targetHost); ok {
			return isCN
		}
	}

	// DNS 查询
	ips, err := net.LookupIP(targetHost)
	if err != nil {
		return false
	}

	isCN := false
	for _, ip := range ips {
		if isChinaIP(ip.String()) {
			isCN = true
			break
		}
	}

	// 缓存结果
	if dnsCache != nil {
		dnsCache.Set(targetHost, ips, isCN, 5*time.Minute)
	}

	return isCN
}

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func isChinaIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	if ip.To4() != nil {
		ipUint32 := ipToUint32(ip)
		if ipUint32 == 0 {
			return false
		}

		chinaIPRangesMu.RLock()
		defer chinaIPRangesMu.RUnlock()

		left, right := 0, len(chinaIPRanges)-1
		for left <= right {
			mid := (left + right) >> 1
			r := chinaIPRanges[mid]
			if ipUint32 < r.start {
				right = mid - 1
			} else if ipUint32 > r.end {
				left = mid + 1
			} else {
				return true
			}
		}
		return false
	}

	// IPv6
	ipBytes := ip.To16()
	if ipBytes == nil {
		return false
	}

	var ipArray [16]byte
	copy(ipArray[:], ipBytes)

	chinaIPV6RangesMu.RLock()
	defer chinaIPV6RangesMu.RUnlock()

	left, right := 0, len(chinaIPV6Ranges)-1
	for left <= right {
		mid := (left + right) >> 1
		r := chinaIPV6Ranges[mid]
		cmpStart := compareIPv6(ipArray, r.start)
		if cmpStart < 0 {
			right = mid - 1
			continue
		}
		cmpEnd := compareIPv6(ipArray, r.end)
		if cmpEnd > 0 {
			left = mid + 1
			continue
		}
		return true
	}
	return false
}

func compareIPv6(a, b [16]byte) int {
	for i := 0; i < 16; i++ {
		if a[i] < b[i] {
			return -1
		} else if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

// ==================== IP 列表加载 ====================

func downloadIPList(urlStr, filePath string) error {
	log.Printf("[下载] 正在下载 IP 列表: %s", urlStr)
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(urlStr)
	if err != nil {
		return fmt.Errorf("下载失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载失败: HTTP %d", resp.StatusCode)
	}

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("读取下载内容失败: %w", err)
	}

	if err := os.WriteFile(filePath, content, 0644); err != nil {
		return fmt.Errorf("保存文件失败: %w", err)
	}

	log.Printf("[下载] 已保存到: %s", filePath)
	return nil
}

func loadChinaIPList() error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("获取可执行文件路径失败: %w", err)
	}
	exeDir := filepath.Dir(exePath)
	ipListFile := filepath.Join(exeDir, "chn_ip.txt")

	if _, err := os.Stat(ipListFile); os.IsNotExist(err) {
		ipListFile = "chn_ip.txt"
	}

	needDownload := false
	if info, err := os.Stat(ipListFile); os.IsNotExist(err) {
		needDownload = true
		log.Printf("[加载] IPv4 列表文件不存在，将自动下载")
	} else if info.Size() == 0 {
		needDownload = true
		log.Printf("[加载] IPv4 列表文件为空，将自动下载")
	}

	if needDownload {
		urlStr := "https://raw.githubusercontent.com/mayaxcn/china-ip-list/refs/heads/master/chn_ip.txt"
		if err := downloadIPList(urlStr, ipListFile); err != nil {
			return fmt.Errorf("自动下载 IPv4 列表失败: %w", err)
		}
	}

	file, err := os.Open(ipListFile)
	if err != nil {
		return fmt.Errorf("打开IP列表文件失败: %w", err)
	}
	defer file.Close()

	var ranges []ipRange
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		startIP := net.ParseIP(parts[0])
		endIP := net.ParseIP(parts[1])
		if startIP == nil || endIP == nil {
			continue
		}
		start := ipToUint32(startIP)
		end := ipToUint32(endIP)
		if start > 0 && end > 0 && start <= end {
			ranges = append(ranges, ipRange{start: start, end: end})
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("读取IP列表文件失败: %w", err)
	}

	if len(ranges) == 0 {
		return errors.New("IP列表为空")
	}

	// 排序
	for i := 0; i < len(ranges)-1; i++ {
		for j := i + 1; j < len(ranges); j++ {
			if ranges[i].start > ranges[j].start {
				ranges[i], ranges[j] = ranges[j], ranges[i]
			}
		}
	}

	chinaIPRangesMu.Lock()
	chinaIPRanges = ranges
	chinaIPRangesMu.Unlock()

	log.Printf("[加载] IPv4 列表加载完成，共 %d 条规则", len(ranges))
	return nil
}

func loadChinaIPV6List() error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("获取可执行文件路径失败: %w", err)
	}
	exeDir := filepath.Dir(exePath)
	ipListFile := filepath.Join(exeDir, "chn_ip_v6.txt")

	if _, err := os.Stat(ipListFile); os.IsNotExist(err) {
		ipListFile = "chn_ip_v6.txt"
	}

	needDownload := false
	if info, err := os.Stat(ipListFile); os.IsNotExist(err) {
		needDownload = true
		log.Printf("[加载] IPv6 列表文件不存在，将自动下载")
	} else if info.Size() == 0 {
		needDownload = true
		log.Printf("[加载] IPv6 列表文件为空，将自动下载")
	}

	if needDownload {
		urlStr := "https://raw.githubusercontent.com/mayaxcn/china-ip-list/refs/heads/master/chn_ip_v6.txt"
		if err := downloadIPList(urlStr, ipListFile); err != nil {
			log.Printf("[警告] 自动下载 IPv6 列表失败: %v", err)
			return nil
		}
	}

	file, err := os.Open(ipListFile)
	if err != nil {
		log.Printf("[警告] 打开 IPv6 IP列表文件失败: %v", err)
		return nil
	}
	defer file.Close()

	var ranges []ipRangeV6
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		startIP := net.ParseIP(parts[0])
		endIP := net.ParseIP(parts[1])
		if startIP == nil || endIP == nil {
			continue
		}
		startBytes := startIP.To16()
		endBytes := endIP.To16()
		if startBytes == nil || endBytes == nil {
			continue
		}
		var start, end [16]byte
		copy(start[:], startBytes)
		copy(end[:], endBytes)
		if compareIPv6(start, end) <= 0 {
			ranges = append(ranges, ipRangeV6{start: start, end: end})
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("读取IPv6 IP列表文件失败: %w", err)
	}

	if len(ranges) == 0 {
		return nil
	}

	// 排序
	for i := 0; i < len(ranges)-1; i++ {
		for j := i + 1; j < len(ranges); j++ {
			if compareIPv6(ranges[i].start, ranges[j].start) > 0 {
				ranges[i], ranges[j] = ranges[j], ranges[i]
			}
		}
	}

	chinaIPV6RangesMu.Lock()
	chinaIPV6Ranges = ranges
	chinaIPV6RangesMu.Unlock()

	log.Printf("[加载] IPv6 列表加载完成，共 %d 条规则", len(ranges))
	return nil
}

// ==================== ECH 相关 ====================

const typeHTTPS = 65

func prepareECH() error {
	echBase64, err := queryHTTPSRecord(echDomain, dnsServer)
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

	log.Printf("[ECH] 配置已加载，长度: %d 字节", len(raw))
	return nil
}

func refreshECH() error {
	log.Printf("[ECH] 刷新配置...")
	return prepareECH()
}

func getECHList() ([]byte, error) {
	echListMu.RLock()
	defer echListMu.RUnlock()
	if len(echList) == 0 {
		return nil, errors.New("ECH 配置未加载")
	}
	result := make([]byte, len(echList))
	copy(result, echList)
	return result, nil
}

func buildTLSConfigWithECH(serverName string, echConfigList []byte) (*tls.Config, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("加载系统根证书失败: %w", err)
	}

	if echConfigList == nil || len(echConfigList) == 0 {
		return nil, errors.New("ECH 配置为空")
	}

	config := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: serverName,
		RootCAs:    roots,
	}

	if err := setECHConfig(config, echConfigList); err != nil {
		return nil, fmt.Errorf("设置 ECH 配置失败: %w", err)
	}

	return config, nil
}

func setECHConfig(config *tls.Config, echConfigList []byte) error {
	configValue := reflect.ValueOf(config).Elem()

	field1 := configValue.FieldByName("EncryptedClientHelloConfigList")
	if !field1.IsValid() || !field1.CanSet() {
		return fmt.Errorf("EncryptedClientHelloConfigList 字段不可用，需要 Go 1.23+")
	}
	field1.Set(reflect.ValueOf(echConfigList))

	field2 := configValue.FieldByName("EncryptedClientHelloRejectionVerify")
	if !field2.IsValid() || !field2.CanSet() {
		return fmt.Errorf("EncryptedClientHelloRejectionVerify 字段不可用")
	}

	rejectionFunc := func(cs tls.ConnectionState) error {
		return errors.New("服务器拒绝 ECH")
	}
	field2.Set(reflect.ValueOf(rejectionFunc))

	return nil
}

func queryHTTPSRecord(domain, dnsServerAddr string) (string, error) {
	dohURL := dnsServerAddr
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

// ==================== WebSocket 连接 ====================

func parseServerAddr(addr string) (host, port, path string, err error) {
	path = "/"
	slashIdx := strings.Index(addr, "/")
	if slashIdx != -1 {
		path = addr[slashIdx:]
		addr = addr[:slashIdx]
	}

	host, port, err = net.SplitHostPort(addr)
	if err != nil {
		return "", "", "", fmt.Errorf("无效的服务器地址格式: %v", err)
	}

	return host, port, path, nil
}

func dialWebSocketWithECHInternal(maxRetries int) (*websocket.Conn, error) {
	host, port, path, err := parseServerAddr(serverAddr)
	if err != nil {
		return nil, err
	}

	wsURL := fmt.Sprintf("wss://%s:%s%s", host, port, path)

	for attempt := 1; attempt <= maxRetries; attempt++ {
		echBytes, echErr := getECHList()
		if echErr != nil {
			if attempt < maxRetries {
				refreshECH()
				continue
			}
			return nil, echErr
		}

		tlsCfg, tlsErr := buildTLSConfigWithECH(host, echBytes)
		if tlsErr != nil {
			return nil, tlsErr
		}

		dialer := websocket.Dialer{
			TLSClientConfig: tlsCfg,
			Subprotocols: func() []string {
				if token == "" {
					return nil
				}
				return []string{token}
			}(),
			HandshakeTimeout: 15 * time.Second,
			ReadBufferSize:   32 * 1024,
			WriteBufferSize:  32 * 1024,
		}

		if serverIP != "" {
			dialer.NetDial = func(network, address string) (net.Conn, error) {
				_, p, err := net.SplitHostPort(address)
				if err != nil {
					return nil, err
				}
				return net.DialTimeout(network, net.JoinHostPort(serverIP, p), 10*time.Second)
			}
		}

		wsConn, _, dialErr := dialer.Dial(wsURL, nil)
		if dialErr != nil {
			if strings.Contains(dialErr.Error(), "ECH") && attempt < maxRetries {
				log.Printf("[ECH] 连接失败，尝试刷新配置 (%d/%d)", attempt, maxRetries)
				refreshECH()
				time.Sleep(time.Second)
				continue
			}
			return nil, dialErr
		}

		return wsConn, nil
	}

	return nil, errors.New("连接失败，已达最大重试次数")
}

func queryDoHForProxy(dnsQuery []byte) ([]byte, error) {
	_, port, _, err := parseServerAddr(serverAddr)
	if err != nil {
		return nil, err
	}

	dohURL := fmt.Sprintf("https://cloudflare-dns.com:%s/dns-query", port)

	echBytes, err := getECHList()
	if err != nil {
		return nil, fmt.Errorf("获取 ECH 配置失败: %w", err)
	}

	tlsCfg, err := buildTLSConfigWithECH("cloudflare-dns.com", echBytes)
	if err != nil {
		return nil, fmt.Errorf("构建 TLS 配置失败: %w", err)
	}

	transport := &http.Transport{
		TLSClientConfig:     tlsCfg,
		MaxIdleConns:        10,
		IdleConnTimeout:     30 * time.Second,
		DisableCompression:  true,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	if serverIP != "" {
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, p, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			dialer := &net.Dialer{Timeout: 10 * time.Second}
			return dialer.DialContext(ctx, network, net.JoinHostPort(serverIP, p))
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	req, err := http.NewRequest("POST", dohURL, bytes.NewReader(dnsQuery))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DoH 请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH 响应错误: %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}
