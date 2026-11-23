package server

// 设置项读取的通用小工具（移植自上游 Pojun）。
// 统一在这里，是为了让各处不再各写一遍字符串→整数/布尔 的解析与默认值。

import (
	"strconv"
	"strings"
)

// intSetting reads an integer setting with a default.
func intSetting(pg interface {
	GetSetting(string) (string, bool, error)
}, key string, def int) int {
	v, ok, err := pg.GetSetting(key)
	if err != nil || !ok {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return def
	}
	return n
}

// settingString reads a string setting (empty when unset).
func settingString(pg interface {
	GetSetting(string) (string, bool, error)
}, key string) string {
	v, _, _ := pg.GetSetting(key)
	return v
}

// boolSetting reads a boolean setting with a default.
func boolSetting(pg interface {
	GetSetting(string) (string, bool, error)
}, key string, def bool) bool {
	v, ok, err := pg.GetSetting(key)
	if err != nil || !ok {
		return def
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	return def
}
