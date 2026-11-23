package egress

// SSH 跳板（v0.7.1）：用一台已授权的主机做 SOCKS5 出口。
//
// 做法：x/crypto/ssh 连上跳板机 → 本地监听 127.0.0.1:随机端口 → 实现最小
// SOCKS5 服务 → 每个 CONNECT 经 ssh.Client.Dial 转发。这样扫描器/worker 只要把
// 代理指向 127.0.0.1:port，流量就从跳板机出去，不需要在跳板上装任何东西。
//
// 边界：只接受显式配置的跳板；不保存明文密钥（密钥在凭据保险库）；监听仅回环。

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

type Provider struct {
	ID           int64  `json:"id"`
	Name         string `json:"name"`
	Host         string `json:"host"`
	Port         int    `json:"port"`
	User         string `json:"user"`
	CredentialID int64  `json:"credential_id,omitempty"`
}

type running struct {
	provider Provider
	ln       net.Listener
	client   *ssh.Client
	addr     string
	started  time.Time
}

type Manager struct {
	mu      sync.Mutex
	running map[int64]*running
}

func NewManager() *Manager { return &Manager{running: map[int64]*running{}} }

type Auth struct {
	Password   string
	PrivateKey string
}

// Start 建立 SSH 连接并在本地起 SOCKS5；返回本地代理地址（socks5://127.0.0.1:port）。
func (m *Manager) Start(ctx context.Context, p Provider, a Auth) (string, error) {
	if p.Host == "" || p.Port <= 0 || p.User == "" {
		return "", errors.New("跳板 host/port/user 必填")
	}
	var methods []ssh.AuthMethod
	if a.PrivateKey != "" {
		signer, err := ssh.ParsePrivateKey([]byte(a.PrivateKey))
		if err != nil {
			return "", fmt.Errorf("私钥解析失败: %w", err)
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}
	if a.Password != "" {
		methods = append(methods, ssh.Password(a.Password))
	}
	if len(methods) == 0 {
		return "", errors.New("缺少密码或私钥")
	}
	cfg := &ssh.ClientConfig{
		User:            p.User,
		Auth:            methods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // 跳板由用户显式配置；后续可加指纹固定
		Timeout:         10 * time.Second,
	}
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	d := net.Dialer{}
	conn, err := d.DialContext(dialCtx, "tcp", net.JoinHostPort(p.Host, strconv.Itoa(p.Port)))
	if err != nil {
		return "", fmt.Errorf("连接跳板失败: %w", err)
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, net.JoinHostPort(p.Host, strconv.Itoa(p.Port)), cfg)
	if err != nil {
		_ = conn.Close()
		return "", fmt.Errorf("SSH 握手失败: %w", err)
	}
	client := ssh.NewClient(c, chans, reqs)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = client.Close()
		return "", err
	}
	r := &running{provider: p, ln: ln, client: client, addr: ln.Addr().String(), started: time.Now()}
	m.mu.Lock()
	if old := m.running[p.ID]; old != nil {
		old.ln.Close()
		old.client.Close()
	}
	m.running[p.ID] = r
	m.mu.Unlock()
	go m.serve(ln, client)
	return "socks5://" + r.addr, nil
}

func (m *Manager) Stop(id int64) bool {
	m.mu.Lock()
	r := m.running[id]
	delete(m.running, id)
	m.mu.Unlock()
	if r == nil {
		return false
	}
	_ = r.ln.Close()
	_ = r.client.Close()
	return true
}

func (m *Manager) Status(id int64) (addr string, since time.Time, ok bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.running[id]
	if r == nil {
		return "", time.Time{}, false
	}
	return "socks5://" + r.addr, r.started, true
}

func (m *Manager) serve(ln net.Listener, client *ssh.Client) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go handleSOCKS(c, client.Dial)
	}
}

// handleSOCKS 是最小 SOCKS5（无认证、CONNECT、IPv4/域名/IPv6）。
func handleSOCKS(c net.Conn, dial func(network, addr string) (net.Conn, error)) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	buf := make([]byte, 512)
	if _, err := io.ReadFull(c, buf[:2]); err != nil {
		return
	}
	if buf[0] != 0x05 {
		return
	}
	n := int(buf[1])
	if _, err := io.ReadFull(c, buf[:n]); err != nil {
		return
	}
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return
	}
	if _, err := io.ReadFull(c, buf[:4]); err != nil {
		return
	}
	if buf[1] != 0x01 { // CONNECT only
		_, _ = c.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	var host string
	switch buf[3] {
	case 0x01:
		if _, err := io.ReadFull(c, buf[:4]); err != nil {
			return
		}
		host = net.IP(buf[:4]).String()
	case 0x03:
		if _, err := io.ReadFull(c, buf[:1]); err != nil {
			return
		}
		l := int(buf[0])
		if _, err := io.ReadFull(c, buf[:l]); err != nil {
			return
		}
		host = string(buf[:l])
	case 0x04:
		if _, err := io.ReadFull(c, buf[:16]); err != nil {
			return
		}
		host = net.IP(buf[:16]).String()
	default:
		return
	}
	if _, err := io.ReadFull(c, buf[:2]); err != nil {
		return
	}
	port := int(binary.BigEndian.Uint16(buf[:2]))
	target := net.JoinHostPort(host, strconv.Itoa(port))
	up, err := dial("tcp", target)
	if err != nil {
		log.Printf("[egress] ssh jump dial %s: %v", target, err)
		_, _ = c.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer up.Close()
	_ = c.SetDeadline(time.Time{})
	if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, c); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, up); done <- struct{}{} }()
	<-done
}
