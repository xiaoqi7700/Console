//go:build windows

package agent

import (
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const createNewProcessGroup = 0x00000200

func jobSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{CreationFlags: createNewProcessGroup}
}

// jobKillGroup 用 taskkill /T 杀整棵进程树（外层 bash + 内层脚本/子进程）。
func jobKillGroup(pid int) error {
	if pid <= 0 {
		return nil
	}
	return exec.Command("taskkill", "/T", "/F", "/PID", strconv.Itoa(pid)).Run()
}

// jobOwnsProcess：Windows 没有轻量的 argv 读取接口（QueryFullProcessImageName 只给
// 可执行文件路径，无法区分同一 bash.exe 的不同作业），保持旧行为按 PID 判活。
// 生产主战场是 Linux；Windows 上的同名重跑/任务清理仍可能受 PID 复用影响。
func jobOwnsProcess(m jobMeta) bool { return m.PID > 0 }

// jobWaitGone 等 taskkill 真正生效：taskkill 返回后进程句柄可能尚未完全释放，
// 紧接着用 tasklist 断言会偶发看到残留项。
func jobWaitGone(pid int, timeout time.Duration) {
	if pid <= 0 {
		return
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if alive, known := jobProcessAlive(pid); known && !alive {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func jobProcessAlive(pid int) (alive bool, known bool) {
	if pid <= 0 {
		return false, true
	}
	out, err := exec.Command("tasklist", "/FI", "PID eq "+strconv.Itoa(pid), "/FO", "CSV", "/NH").Output()
	if err != nil {
		return true, false
	}
	return strings.Contains(string(out), strconv.Itoa(pid)), true
}
