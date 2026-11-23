#!/bin/sh
# run.sh —— 后台静默启动 ARTEX（自动轮转日志、不往终端刷屏）
#
# 为什么需要它：start.sh 只是守护壳，日志打到哪由调用方的重定向决定；
# 直接 `./start.sh` 会把 50 个 worker 的日志全刷在终端里，行数一多终端渲染
# 本身就拖慢整机。run.sh 固定把 stdout/stderr 落到 artex.log，并打开
# ARTEX_LOG_QUIET=1（stderr 静默，但页面「后端日志」照旧，因为内存环 +
# server_logs 落库不受影响）。
#
# 用法：
#   ./run.sh               后台启动（推荐）
#   ./run.sh --foreground  前台启动但静默（Ctrl-C 退出）
#   ./run.sh --stop        停止（先停 start.sh 壳，它会把 TERM 转给 artex）
#   ./run.sh -addr :8787 -proxy 127.0.0.1:8788   额外参数原样透传给 artex
set -u
cd "$(dirname "$0")" || exit 1

LOG=artex.log
MAX_BYTES=52428800 # 50MB：超过就在启动前归档，避免长期运行把磁盘写满

rotate() {
	[ -f "$LOG" ] || return 0
	size=$(wc -c <"$LOG" 2>/dev/null || echo 0)
	if [ "${size:-0}" -gt "$MAX_BYTES" ]; then
		mv "$LOG" "artex.log.$(date +%Y%m%d-%H%M%S)"
		echo "[run] 日志已归档"
	fi
}

stop() {
	if pgrep -f "bin/sh ./start.sh" >/dev/null 2>&1; then
		pkill -f "bin/sh ./start.sh"
		echo "[run] 已发送停止信号（start.sh 会把 TERM 转给 artex）"
	elif pgrep -f "^\./artex" >/dev/null 2>&1; then
		pkill -f "^\./artex"
		echo "[run] 已发送停止信号"
	else
		echo "[run] 没有在跑的实例"
	fi
}

# guard：单实例保护。第二个实例绑不上 :8787 / :8788，start.sh 会把它当
# 「崩溃」无限重启（1→2→4…60s），还会在每次启动时抢同一个库的意图。
guard() {
	pid=$(lsof -nP -iTCP:8787 -sTCP:LISTEN -t 2>/dev/null | head -1)
	[ -n "$pid" ] || pid=$(lsof -nP -iTCP:8788 -sTCP:LISTEN -t 2>/dev/null | head -1)
	if [ -n "$pid" ] || pgrep -f "bin/sh ./start.sh" >/dev/null 2>&1; then
		echo "[run] 已经在运行了（artex pid=${pid:-?}，端口 8787/8788 被占用）。"
		echo "      要重启就先 ./run.sh --stop，等端口释放后再 ./run.sh"
		exit 1
	fi
}

case "${1:-}" in
	--stop)
		stop
		exit 0
		;;
	--foreground)
		shift
		guard
		rotate
		ARTEX_LOG_QUIET=1 exec ./start.sh "$@"
		;;
esac

guard
rotate
# 后台模式不设 ARTEX_LOG_QUIET：日志落到 artex.log 是为了事后排查，
# 写文件本身不慢；真正拖慢整机的是「把海量日志渲染在终端里」。
# 想连文件都不写，可以自己前置 ARTEX_LOG_QUIET=1 ./run.sh。
nohup ./start.sh "$@" >>"$LOG" 2>&1 &
echo "[run] 已后台启动 pid=$!（日志 ${LOG}，终端保持安静）"
