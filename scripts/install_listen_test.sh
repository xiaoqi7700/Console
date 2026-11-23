#!/usr/bin/env bash
# install.sh 监听地址归一的纯 shell 回归。
#
# 背景：CI 只有 `bash -n install.sh`（语法），normalize_listen 的 IPv6/zone/
# 端口边界/空 host 分支、旧暴露面地址判定都靠人工回归。本脚本从 install.sh
# 抽取 LISTEN_HELPERS 标记之间的函数，做输入矩阵断言。
#
# 只依赖 bash + coreutils；不联网、不写系统路径。
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/install.sh"
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

sed -n '/^# >>> LISTEN_HELPERS/,/^# <<< LISTEN_HELPERS/p' "$SRC" >"$TMP"
if [ ! -s "$TMP" ]; then
  echo "FAIL: install.sh 里找不到 LISTEN_HELPERS 标记" >&2
  exit 1
fi

fail=0
# 被测函数依赖的最小桩：真正执行时会 die/warn，测试里只记录。
die(){ printf 'DIE: %s\n' "$*" >&2; exit 1; }
warn(){ :; }
info(){ :; }
MODE="binary"
IS_MAC=0
LISTEN_EXPLICIT=0
LISTEN_ADDR="127.0.0.1:8787"

# shellcheck disable=SC1090
. "$TMP"

ok_case(){ printf 'ok   %s\n' "$1"; }
fail_case(){ printf 'FAIL %s\n  期望: %s\n  实际: %s\n' "$1" "$2" "$3" >&2; fail=1; }

check(){ # desc expected actual
  if [ "$2" = "$3" ]; then ok_case "$1"; else fail_case "$1" "$2" "$3"; fi
}

# 归一化一例，输出 "LISTEN|PORT|PROBE|PUBLISH"。
run(){
  local raw="$1" explicit="${2:-0}" mode="${3:-binary}"
  (
    LISTEN_ADDR="$raw"
    LISTEN_EXPLICIT="$explicit"
    MODE="$mode"
    IS_MAC=0
    normalize_listen
    printf '%s|%s|%s|%s\n' "$LISTEN_ADDR" "$LISTEN_PORT" "$PROBE_HOST" "$PUBLISH_HOST"
  )
}

expect_die(){ # desc raw pattern [mode]
  local desc="$1" raw="$2" pat="$3" mode="${4:-binary}" out rc
  out="$(
    LISTEN_ADDR="$raw"; LISTEN_EXPLICIT=1; MODE="$mode"; IS_MAC=0
    normalize_listen 2>&1
  )"
  rc=$?
  if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q -- "$pat"; then
    ok_case "$desc"
  else
    fail_case "$desc" "rc!=0 且含 '$pat'" "rc=$rc out=$out"
  fi
}

echo "== normalize_listen 输入矩阵 =="
check "默认：回环 8787" \
  "127.0.0.1:8787|8787|127.0.0.1|127.0.0.1" "$(run "" 0)"
check "纯端口：默认 host 回环" \
  "127.0.0.1:9000|9000|127.0.0.1|127.0.0.1" "$(run "9000" 1)"
check "空 host：所有接口" \
  ":8787|8787|127.0.0.1|" "$(run ":8787" 1)"
check "0.0.0.0：所有接口" \
  "0.0.0.0:8787|8787|127.0.0.1|0.0.0.0" "$(run "0.0.0.0:8787" 1)"
check "localhost 归一为回环" \
  "127.0.0.1:9000|9000|127.0.0.1|127.0.0.1" "$(run "localhost:9000" 1)"
check "具体 IPv4：绑该网卡" \
  "1.2.3.4:9000|9000|1.2.3.4|1.2.3.4" "$(run "1.2.3.4:9000" 1)"
check "IPv6 回环" \
  "[::1]:9000|9000|[::1]|[::1]" "$(run "[::1]:9000" 1)"
check "IPv6 通配" \
  "[::]:8787|8787|[::1]|[::]" "$(run "[::]:8787" 1)"
check "IPv6 具体地址" \
  "[2001:db8::1]:8787|8787|[2001:db8::1]|[2001:db8::1]" "$(run "[2001:db8::1]:8787" 1)"

expect_die "显式空值报错" "" "监听地址不能为空"
expect_die "非法端口（非数字）" "abc" "监听端口不合法"
expect_die "非法端口（0）" "0" "监听端口越界"
expect_die "非法端口（越界）" "70000" "监听端口越界"
expect_die "非法 IPv4 报地址非法" "1.2.3.400:8787" "非法的 IPv4 地址"
expect_die "主机名被拒绝" "example.com:8787" "不支持的主机名"
expect_die "IPv6 缺方括号" "::1:8787" "IPv6 地址必须写成"
expect_die "IPv6 zone 被拒绝" "[fe80::1%eth0]:8787" "IPv6 zone"
expect_die "空 IPv6 被拒绝" "[]:8787" "非法的 IPv6 地址"
expect_die "Docker 不支持 IPv6 发布" "[::1]:8787" "Docker 发布不支持 IPv6" docker

echo "== 回环判定 =="
for a in "127.0.0.1:8787" "127.1.2.3:1" "localhost:8787" "[::1]:8787"; do
  if addr_is_loopback "$a"; then ok_case "回环 $a"; else fail_case "回环 $a" "true" "false"; fi
done
for a in ":8787" "0.0.0.0:8787" "[::]:8787" "192.168.1.5:8787" "8787"; do
  if addr_is_loopback "$a"; then fail_case "非回环 $a" "false" "true"; else ok_case "非回环 $a"; fi
done

echo "== compose 宿主映射判定 =="
for m in "127.0.0.1:8787:8787" "[::1]:8787:8787"; do
  if compose_host_exposed "$m"; then fail_case "未暴露 $m" "false" "true"; else ok_case "未暴露 $m"; fi
done
for m in "8787:8787" "9000:8787" "0.0.0.0:8787:8787" "192.168.1.5:8787:8787" "[::]:8787:8787"; do
  if compose_host_exposed "$m"; then ok_case "已暴露 $m"; else fail_case "已暴露 $m" "true" "false"; fi
done

echo "== PORTMAP 生成 =="
check "无 host → 裸端口映射" "8787:8787" "$(compose_portmap 8787 "")"
check "0.0.0.0 host" "0.0.0.0:8787:8787" "$(compose_portmap 8787 "0.0.0.0")"
check "具体 IP + 自定义端口" "127.0.0.1:9000:8787" "$(compose_portmap 9000 "127.0.0.1")"
check "IPv6 host" "[::1]:8787:8787" "$(compose_portmap 8787 "[::1]")"

echo "== 旧安装地址提取 =="
FIX="$(mktemp -d)"
trap 'rm -f "$TMP"; rm -rf "$FIX"' EXIT
printf '%s\n' 'ExecStart=/opt/pojun/start.sh -addr :9000' >"$FIX/unit-port"
printf '%s\n' 'ExecStart=/opt/pojun/start.sh -addr 127.0.0.1:8787' >"$FIX/unit-loop"
printf '%s\n' 'ExecStart=/opt/pojun/start.sh -addr=0.0.0.0:8787' >"$FIX/unit-eq"
printf '%s\n%s\n' '<string>-addr</string>' '<string>[::1]:8787</string>' >"$FIX/plist"
check "unit：--listen=:9000" ":9000" "$(unit_addr_value "$FIX/unit-port")"
check "unit：回环" "127.0.0.1:8787" "$(unit_addr_value "$FIX/unit-loop")"
check "unit：-addr= 写法" "0.0.0.0:8787" "$(unit_addr_value "$FIX/unit-eq")"
check "plist：-addr 下一项" "[::1]:8787" "$(plist_addr_value "$FIX/plist")"
if addr_is_loopback "$(unit_addr_value "$FIX/unit-port")"; then
  fail_case "unit --listen=:9000 判为暴露" "false" "true"
else
  ok_case "unit --listen=:9000 判为暴露"
fi

if [ "$fail" -ne 0 ]; then
  echo "FAILED" >&2
  exit 1
fi
echo "all passed"
