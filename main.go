package main

import (
	"bufio"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 检测返回包中是否含有 AsyncRAT 心跳包报文
func checkAndDisconnect(response []byte) bool {
	hexString := hex.EncodeToString(response)
	return strings.Contains(hexString, "0000001f8b08000000000004006b5c1690989c9d5ab2a4203f2f1d009e9331870d000000")
}

// 检测返回包中是否含有 AsyncRAT低版本 心跳包报文
func check2AndDisconnect(response []byte) bool {
	hexString := hex.EncodeToString(response)
	return strings.Contains(hexString, "a65061636b6574a86368617445786974")
}

func isTLSPort(host string, port int) bool {
	portStr := strconv.Itoa(port)
	address := net.JoinHostPort(host, portStr)

	// 尝试建立 TLS 连接
	conf := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS13,
	}

	dialer := &net.Dialer{
		Timeout: 3 * time.Second, // 设置连接超时时间
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", address, conf)
	if err != nil {
		// 捕获更具体的错误信息
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			// fmt.Println("连接超时")
		} else if opErr, ok := err.(*net.OpError); ok {
			if opErr.Op == "dial" {
				// fmt.Println("无法建立TCP连接")
			} else if opErr.Op == "read" {
				// fmt.Println("读取错误")
			}
		} else if strings.Contains(err.Error(), "handshake failure") {
			// fmt.Println("TLS握手失败")
		} else if strings.Contains(err.Error(), "protocol version not supported") {
			// fmt.Println("不支持的协议版本")
		} else {
			// fmt.Printf("其他连接错误: %v\n", err)
		}
		return false
	}
	defer conn.Close()

	// 连接成功，说明端口是 TLS 端口
	return true
}

// 发送十六进制数据到服务器
func sendHexData(hexData string, host string, port int, mode int, timeout time.Duration) bool {
	data, err := hex.DecodeString(hexData)
	if err != nil {
		fmt.Printf("十六进制数据格式错误: %v\n", err)
		return false
	}

	conf := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10, // 允许 TLS 1.0
		MaxVersion:         tls.VersionTLS13, // 最高支持到 TLS 1.3
	}

	dialer := &net.Dialer{
		Timeout: timeout,
	}

	// 尝试连接到服务器
	conn, err := tls.DialWithDialer(dialer, "tcp", fmt.Sprintf("%s:%d", host, port), conf)
	if err != nil {
		fmt.Printf("连接错误: %v\n", err)
		return false
	}
	defer conn.Close()

	// 成功建立连接，发送数据
	_, err = conn.Write(data)
	if err != nil {
		fmt.Printf("发送数据错误: %v\n", err)
		return false
	}

	// 等待响应
	response := make([]byte, 1024)
	for {
		conn.SetReadDeadline(time.Now().Add(timeout)) // 设置读取超时
		n, err := conn.Read(response)
		if err != nil {
			if err.Error() != "EOF" {
				fmt.Printf("读取响应错误: %v\n", err)
			}
			break
		}
		if n > 0 {
			// 检查响应是否符合预期
			if mode == 1 && checkAndDisconnect(response[:n]) {
				return true
			} else if mode == 2 && check2AndDisconnect(response[:n]) {
				return true
			}
		}
	}

	fmt.Println("未检测到匹配的响应")
	return false
}

// 检测心跳包
func heartbeatPacket(host string, port int, outputFile *os.File, mu *sync.Mutex) bool {
	hexData := "350000001c0000001f8b08000000000004006b5a1690989c9d5ab22420332f7db96f6a7171627aeab2273bba5fecdd0b0061cb9caf1c000000"
	hexDataLow := "2700000082a65061636b6574a450696e67a74d657373616765b14350552032342520202052414d203633252800000082a65061636b6574a463686174aa5772697465496e707574af6d61633a2031313131313131310d0a"

	if sendHexData(hexData, host, port, 1, 5*time.Second) {
		result := fmt.Sprintf("[+] %s:%d 心跳包回显\n", host, port)
		mu.Lock()
		outputFile.WriteString(result)
		mu.Unlock()
		return true
	} else if sendHexData(hexDataLow, host, port, 2, 5*time.Second) {
		result := fmt.Sprintf("[+] %s:%d 低版本心跳包回显\n", host, port)
		mu.Lock()
		outputFile.WriteString(result)
		mu.Unlock()
		return true
	} else {
		result := fmt.Sprintf("[-] %s:%d 无心跳包回显\n", host, port)
		mu.Lock()
		outputFile.WriteString(result)
		mu.Unlock()
		return false
	}
}

func sniffTLSHandshake(hostname string, port int) (bool, string) {
	address := fmt.Sprintf("%s:%d", hostname, port)

	// 首先尝试 TLS 1.0
	result, version := tryTLSVersion(address, tls.VersionTLS10)
	if result {
		return true, version
	}

	// 如果 TLS 1.0 失败，尝试其他版本
	versions := []uint16{
		tls.VersionTLS13,
		tls.VersionTLS12,
		tls.VersionTLS11,
		0x0300, // SSL 3.0
	}

	for _, v := range versions {
		result, version := tryTLSVersion(address, v)
		if result {
			return true, version
		}
	}

	return false, "Unknown"
}

func tryTLSVersion(address string, version uint16) (bool, string) {
	conf := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         version,
		MaxVersion:         version,
	}

	conn, err := tls.Dial("tcp", address, conf)
	if err != nil {
		fmt.Printf("TLS %v 连接错误: %v\n", versionToString(version), err)
		return false, ""
	}
	defer conn.Close()

	state := conn.ConnectionState()
	for _, cert := range state.PeerCertificates {
		if strings.Contains(cert.Subject.String(), "AsyncRAT") {
			return true, versionToString(state.Version)
		}
	}

	fmt.Printf("TLS %v 连接成功，但未找到 AsyncRAT\n", versionToString(state.Version))
	return false, versionToString(state.Version)
}

func versionToString(version uint16) string {
	switch version {
	case tls.VersionSSL30:
		return "SSL 3.0"
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (%d)", version)
	}
}

func tls_handshake_check(hostname string, port int, outputFile *os.File, mu *sync.Mutex) {
	result, version := sniffTLSHandshake(hostname, port)
	if result {
		result := fmt.Sprintf("[+] %s:%d 'AsyncRAT' found in TLS handshake using %s.\n", hostname, port, version)
		mu.Lock()
		outputFile.WriteString(result)
		mu.Unlock()
	} else {
		result := fmt.Sprintf("[-] %s:%d 'AsyncRAT' not found in TLS handshake. Last attempted version: %s.\n", hostname, port, version)
		mu.Lock()
		outputFile.WriteString(result)
		mu.Unlock()
	}
}

func parsePorts(portStr string) []int {
	var ports []int
	if strings.Contains(portStr, "-") {
		rangeParts := strings.Split(portStr, "-")
		start, _ := strconv.Atoi(rangeParts[0])
		end, _ := strconv.Atoi(rangeParts[1])
		for i := start; i <= end; i++ {
			ports = append(ports, i)
		}
	} else {
		portList := strings.Split(portStr, ",")
		for _, port := range portList {
			p, _ := strconv.Atoi(port)
			ports = append(ports, p)
		}
	}
	return ports
}

func parseIPRange(ipRange string) []string {
	var ips []string
	if strings.Contains(ipRange, "/") {
		ip, ipNet, _ := net.ParseCIDR(ipRange)
		for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); inc(ip) {
			ips = append(ips, ip.String())
		}
	} else {
		ips = append(ips, ipRange)
	}
	return ips
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func batchDetect(targetFile, portFile string, maxConcurrent int, enableLimit bool) {
	targetContent, err := ioutil.ReadFile(targetFile)
	if err != nil {
		fmt.Printf("Failed to read target file: %v\n", err)
		return
	}

	portContent, err := ioutil.ReadFile(portFile)
	if err != nil {
		fmt.Printf("Failed to read port file: %v\n", err)
		return
	}

	ports := parsePorts(string(portContent))

	scanner := bufio.NewScanner(strings.NewReader(string(targetContent)))
	var wg sync.WaitGroup
	var mu sync.Mutex
	outputFile, err := os.Create("output.txt")
	if err != nil {
		fmt.Printf("Failed to create output file: %v\n", err)
		return
	}
	defer outputFile.Close()

	start := time.Now()
	sem := make(chan struct{}, maxConcurrent) // 创建一个信号量

	for scanner.Scan() {
		target := scanner.Text()
		if strings.Contains(target, ":") {
			parts := strings.Split(target, ":")
			host := parts[0]
			port, _ := strconv.Atoi(parts[1])
			if enableLimit {
				sem <- struct{}{} // 获取信号量
			}
			wg.Add(1)
			go func(host string, port int) {
				defer wg.Done()
				defer func() {
					if enableLimit {
						<-sem // 释放信号量
					}
				}()
				result := fmt.Sprintf("正在检测: %s:%d\n", host, port)
				if isTLSPort(host, port) {
					heartbeatPacket(host, port, outputFile, &mu)
					tls_handshake_check(host, port, outputFile, &mu)
				} else {
					result += "not tls\n"
				}
				result += fmt.Sprintf("检测完成: %s:%d\n\n", host, port)
				// mu.Lock()
				// outputFile.WriteString(result)
				// mu.Unlock()
			}(host, port)
		} else {
			hosts := parseIPRange(target)
			for _, host := range hosts {
				for _, port := range ports {
					if enableLimit {
						sem <- struct{}{} // 获取信号量
					}
					wg.Add(1)
					go func(host string, port int) {
						defer wg.Done()
						defer func() {
							if enableLimit {
								<-sem // 释放信号量
							}
						}()
						result := fmt.Sprintf("正在检测: %s:%d\n", host, port)
						if isTLSPort(host, port) {
							heartbeatPacket(host, port, outputFile, &mu)
							tls_handshake_check(host, port, outputFile, &mu)
						} else {
							result += "not tls\n"
						}
						result += fmt.Sprintf("检测完成: %s:%d\n\n", host, port)
						// mu.Lock()
						// outputFile.WriteString(result)
						// mu.Unlock()
					}(host, port)
				}
			}
		}
	}

	wg.Wait()
	elapsed := time.Since(start)
	outputFile.WriteString(fmt.Sprintf("总运行时长: %s\n", elapsed))
	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading file: %v\n", err)
	}
}

func main() {
	if len(os.Args) < 3 || len(os.Args) > 5 {
		fmt.Println("Usage: go run main.go <target_file> <port_file> [--limit <max_concurrent>]")
		os.Exit(1)
	}

	targetFile := os.Args[1]
	portFile := os.Args[2]
	maxConcurrent := 750
	enableLimit := true

	if len(os.Args) == 5 && os.Args[3] == "--limit" {
		maxConcurrent, _ = strconv.Atoi(os.Args[4])
	} else if len(os.Args) == 4 && os.Args[3] == "--no-limit" {
		enableLimit = false
	}

	batchDetect(targetFile, portFile, maxConcurrent, enableLimit)
}
