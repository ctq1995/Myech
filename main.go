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
	"os/exec"
	"path/filepath"
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
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/gorilla/websocket"
	"golang.org/x/sys/windows/registry"
)


// 自定义深色主题
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
var (
	listenAddr  string
	serverAddr  string
	serverIP    string
	token       string
	dnsServer   string
	echDomain   string
	routingMode string
	autoProxy   bool // 新增：是否自动设置系统代理

	echListMu sync.RWMutex
	echList   []byte

	chinaIPRangesMu sync.RWMutex
	chinaIPRanges   []ipRange

	chinaIPV6RangesMu sync.RWMutex
	chinaIPV6Ranges   []ipRangeV6

	totalUpload   atomic.Uint64
	totalDownload atomic.Uint64
	isRunning     atomic.Bool
	proxyListener net.Listener
	statusText    = binding.NewString()
	uploadSpeed   = binding.NewString()
	downloadSpeed = binding.NewString()
	logMutex      sync.Mutex
	currentLogs   []string
	logTextWidget *widget.Entry // 使用 Entry 显示日志
)


// 系统代理设置
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
		// 启用代理
		if err := key.SetDWordValue("ProxyEnable", 1); err != nil {
			return fmt.Errorf("设置 ProxyEnable 失败: %w", err)
		}
		if err := key.SetStringValue("ProxyServer", proxyAddr); err != nil {
			return fmt.Errorf("设置 ProxyServer 失败: %w", err)
		}
		// 设置不代理的地址
		bypass := "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;<local>"
		if err := key.SetStringValue("ProxyOverride", bypass); err != nil {
			return fmt.Errorf("设置 ProxyOverride 失败: %w", err)
		}
		log.Printf("[系统代理] 已启用: %s", proxyAddr)
	} else {
		// 禁用代理
		if err := key.SetDWordValue("ProxyEnable", 0); err != nil {
			return fmt.Errorf("禁用代理失败: %w", err)
		}
		log.Printf("[系统代理] 已禁用")
	}

	// 通知系统代理设置已更改
	refreshSystemProxy()
	return nil
}

// 刷新系统代理设置（通知IE/Edge等应用）
func refreshSystemProxy() {
	if runtime.GOOS == "windows" {
		// 使用 PowerShell 刷新代理设置
		cmd := exec.Command("powershell", "-Command",
			`[System.Net.WebRequest]::DefaultWebProxy = [System.Net.WebRequest]::GetSystemWebProxy()`)
		cmd.Run()
	}
}


type ipRange struct {
	start uint32
	end   uint32
}

type ipRangeV6 struct {
	start [16]byte
	end   [16]byte
}
type guiLogWriter struct{}

func (w *guiLogWriter) Write(p []byte) (n int, err error) {
	msg := string(bytes.TrimSpace(p))
	os.Stdout.Write(p)

	logMutex.Lock()
	timeStr := time.Now().Format("15:04:05")
	logLine := fmt.Sprintf("[%s] %s", timeStr, msg)
	currentLogs = append(currentLogs, logLine)

	// 只保留最新100条
	if len(currentLogs) > 100 {
		currentLogs = currentLogs[len(currentLogs)-100:]
	}

	// 合并为单个字符串
	logText := strings.Join(currentLogs, "\n")
	logMutex.Unlock()

	// 更新日志显示
	if logTextWidget != nil {
		fyne.Do(func() {
			logTextWidget.SetText(logText)
			// 滚动到底部
			logTextWidget.CursorRow = len(currentLogs)
		})
	}

	return len(p), nil
}


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

// 创建带标签的输入框组件
func createLabeledEntry(label string, entry *widget.Entry) *fyne.Container {
	lbl := widget.NewLabel(label)
	lbl.TextStyle = fyne.TextStyle{Bold: true}
	return container.NewBorder(nil, nil, container.NewGridWrap(fyne.NewSize(100, 30), lbl), nil, entry)
}

// 创建带标签的选择框组件
func createLabeledSelect(label string, sel *widget.Select) *fyne.Container {
	lbl := widget.NewLabel(label)
	lbl.TextStyle = fyne.TextStyle{Bold: true}
	return container.NewBorder(nil, nil, container.NewGridWrap(fyne.NewSize(100, 30), lbl), nil, sel)
}

// 创建卡片容器
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


// 创建状态指示器
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

func main() {
	log.SetOutput(&guiLogWriter{})
	log.SetFlags(0)

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

	// 上传下载总量绑定
	uploadTotal := binding.NewString()
	uploadTotal.Set("0 B")
	downloadTotal := binding.NewString()
	downloadTotal.Set("0 B")

	// ========== 状态面板 ==========
	statusIndicator := createStatusIndicator(false)
	statusLabel := widget.NewLabelWithData(statusText)
	statusLabel.TextStyle = fyne.TextStyle{Bold: true}

	statusRow := container.NewHBox(
		statusIndicator,
		widget.NewLabel("状态:"),
		statusLabel,
	)

	// 速度和流量使用固定宽度标签
	uploadSpeedLabel := widget.NewLabelWithData(uploadSpeed)
	downloadSpeedLabel := widget.NewLabelWithData(downloadSpeed)
	uploadTotalLabel := widget.NewLabelWithData(uploadTotal)
	downloadTotalLabel := widget.NewLabelWithData(downloadTotal)

	// 固定宽度的标签容器
	createFixedLabel := func(text string, width float32) *fyne.Container {
		lbl := widget.NewLabel(text)
		return container.NewGridWrap(fyne.NewSize(width, 25), lbl)
	}

	createFixedValueLabel := func(label *widget.Label, width float32) *fyne.Container {
		return container.NewGridWrap(fyne.NewSize(width, 25), label)
	}

	// 速度行
	speedRow := container.NewHBox(
		widget.NewIcon(theme.UploadIcon()),
		createFixedLabel("上传:", 45),
		createFixedValueLabel(uploadSpeedLabel, 90),
		widget.NewSeparator(),
		widget.NewIcon(theme.DownloadIcon()),
		createFixedLabel("下载:", 45),
		createFixedValueLabel(downloadSpeedLabel, 90),
	)

	// 流量行
	trafficRow := container.NewHBox(
		createFixedLabel("↑ 已上传:", 75),
		createFixedValueLabel(uploadTotalLabel, 90),
		widget.NewSeparator(),
		createFixedLabel("↓ 已下载:", 75),
		createFixedValueLabel(downloadTotalLabel, 90),
	)

	statsContent := container.NewVBox(
		container.NewPadded(statusRow),
		widget.NewSeparator(),
		container.NewPadded(speedRow),
		widget.NewSeparator(),
		container.NewPadded(trafficRow),
	)
	statsCard := createCard("📊 运行状态", statsContent)

	// ========== 配置面板 ==========
	labelWidth := float32(90)
	entryWidth := float32(260)

	// 统一的表单行创建函数
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

	// 修复：先创建 Select，不立即设置选中值
	routingSelect := widget.NewSelect([]string{"global", "bypass_cn", "none"}, func(s string) {
		routingMode = s
	})
	routingSelect.PlaceHolder = "选择分流模式"

	autoProxyCheck := widget.NewCheck("启动时自动设置系统代理", func(checked bool) {
		autoProxy = checked
		prefs.SetBool("autoProxy", autoProxy)
	})
	autoProxyCheck.SetChecked(autoProxy)

	// 使用统一的 createFormRow 创建所有配置项
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
			isRunning.Store(false)

			// 关闭系统代理
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

				// 设置系统代理
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

	// 使用 Max 容器包装左侧面板，确保固定宽度
	leftPanelWithPadding := container.NewPadded(leftPanel)
	leftContainer := container.NewGridWrap(fyne.NewSize(420, 680), leftPanelWithPadding)

	// ========== 日志面板 ==========
	logTextWidget = widget.NewMultiLineEntry()
	logTextWidget.Wrapping = fyne.TextWrapWord
	logTextWidget.TextStyle = fyne.TextStyle{Monospace: true}
	logTextWidget.Disable() // 只读

	logScroll := container.NewScroll(logTextWidget)
	logScroll.SetMinSize(fyne.NewSize(400, 600))
	logCard := createCard("📝 运行日志", logScroll)

	// ========== 主布局 ==========
	mainContent := container.NewBorder(
		nil, nil,
		leftContainer, nil,
		logCard,
	)

	// 底部状态栏
	versionLabel := widget.NewLabel("ECH Proxy v1.0")
	versionLabel.TextStyle = fyne.TextStyle{Italic: true}

	bottomBar := container.NewBorder(
		widget.NewSeparator(),
		nil, nil, nil,
		container.NewPadded(versionLabel),
	)

	// 最终布局
	content := container.NewBorder(nil, bottomBar, nil, nil, mainContent)
	myWindow.SetContent(content)

	// 修复：在设置内容后再设置 Select 的选中值
	routingSelect.SetSelected(routingMode)

	// 流量监控定时器
	go func() {
		ticker := time.NewTicker(1 * time.Second)
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

			fyne.Do(func() {
				uploadSpeed.Set(upSpd)
				downloadSpeed.Set(downSpd)
				uploadTotal.Set(upTotal)
				downloadTotal.Set(downTotal)
			})
		}
	}()

	// 窗口关闭清理
	myWindow.SetOnClosed(func() {
		if isRunning.Load() {
			if proxyListener != nil {
				proxyListener.Close()
			}
			if autoProxy {
				setSystemProxy(false, "")
			}
		}
	})

	// 修复：使用 Canvas 的 SetOnTypedKey 确保布局完成后刷新
	myWindow.Canvas().SetOnTypedKey(func(ke *fyne.KeyEvent) {})
	
	// 延迟刷新，确保所有组件初始化完成
	go func() {
		time.Sleep(200 * time.Millisecond)
		fyne.Do(func() {
			myWindow.Content().Refresh()
			// 再次刷新确保布局正确
			time.Sleep(50 * time.Millisecond)
			myWindow.Canvas().Content().Refresh()
		})
	}()

	myWindow.ShowAndRun()
}


type TrafficConn struct {
	net.Conn
}

func (c *TrafficConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if n > 0 {
		totalUpload.Add(uint64(n))
	}
	return
}

func (c *TrafficConn) Write(b []byte) (n int, err error) {
	n, err = c.Conn.Write(b)
	if n > 0 {
		totalDownload.Add(uint64(n))
	}
	return
}

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
					log.Printf("[代理] Accept 错误: %v", err)
				}
				return
			}
			wrappedConn := &TrafficConn{Conn: conn}
			go handleConnection(wrappedConn)
		}
	}()
	return nil
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
		left, right := 0, len(chinaIPRanges)
		for left < right {
			mid := (left + right) / 2
			r := chinaIPRanges[mid]
			if ipUint32 < r.start {
				right = mid
			} else if ipUint32 > r.end {
				left = mid + 1
			} else {
				return true
			}
		}
		return false
	}
	ipBytes := ip.To16()
	if ipBytes == nil {
		return false
	}
	var ipArray [16]byte
	copy(ipArray[:], ipBytes)
	chinaIPV6RangesMu.RLock()
	defer chinaIPV6RangesMu.RUnlock()
	left, right := 0, len(chinaIPV6Ranges)
	for left < right {
		mid := (left + right) / 2
		r := chinaIPV6Ranges[mid]
		cmpStart := compareIPv6(ipArray, r.start)
		if cmpStart < 0 {
			right = mid
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
	return nil
}

func shouldBypassProxy(targetHost string) bool {
	if routingMode == "none" {
		return true
	}
	if routingMode == "global" {
		return false
	}
	if routingMode == "bypass_cn" {
		if ip := net.ParseIP(targetHost); ip != nil {
			return isChinaIP(targetHost)
		}
		ips, err := net.LookupIP(targetHost)
		if err != nil {
			return false
		}
		for _, ip := range ips {
			if isChinaIP(ip.String()) {
				return true
			}
		}
		return false
	}
	return false
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
		strings.Contains(errStr, "normal closure")
}
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
	return echList, nil
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
		TLSClientConfig: tlsCfg,
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

func dialWebSocketWithECH(maxRetries int) (*websocket.Conn, error) {
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
			HandshakeTimeout: 10 * time.Second,
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
				log.Printf("[SOCKS5] %s 代理失败: %v", clientAddr, err)
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
	buf := make([]byte, 65535)
	for {
		select {
		case <-stopChan:
			return
		default:
		}
		udpConn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, addr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return
		}
		if n < 10 {
			continue
		}
		data := buf[:n]
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
		udpData := data[headerLen:]
		if dstPort == 53 {
			go handleDNSQuery(udpConn, addr, udpData, data[:headerLen])
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

const (
	modeSOCKS5      = 1
	modeHTTPConnect = 2
	modeHTTPProxy   = 3
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
	wsConn, err := dialWebSocketWithECH(2)
	if err != nil {
		sendErrorResponse(conn, mode)
		return err
	}
	defer wsConn.Close()
	var mu sync.Mutex
	stopPing := make(chan bool)
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				mu.Lock()
				wsConn.WriteMessage(websocket.PingMessage, nil)
				mu.Unlock()
			case <-stopPing:
				return
			}
		}
	}()
	defer close(stopPing)
	conn.SetDeadline(time.Time{})
	if firstFrame == "" && mode == modeSOCKS5 {
		conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		buffer := make([]byte, 32768)
		n, _ := conn.Read(buffer)
		conn.SetReadDeadline(time.Time{})
		if n > 0 {
			firstFrame = string(buffer[:n])
		}
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
	go func() {
		buf := make([]byte, 32768)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				mu.Lock()
				wsConn.WriteMessage(websocket.TextMessage, []byte("CLOSE"))
				mu.Unlock()
				done <- true
				return
			}
			mu.Lock()
			err = wsConn.WriteMessage(websocket.BinaryMessage, buf[:n])
			mu.Unlock()
			if err != nil {
				done <- true
				return
			}
		}
	}()
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
	done := make(chan bool, 2)
	go func() {
		io.Copy(targetConn, conn)
		done <- true
	}()
	go func() {
		io.Copy(conn, targetConn)
		done <- true
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
