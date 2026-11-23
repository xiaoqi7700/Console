#!/usr/bin/env bash
# pojun — PostgreSQL 一键配置
#
# 只做三件事：建/同步角色、建库并设属主、把密码写回 config.json。
# 不改 pg_hba.conf、不改 postgresql.conf、不动任何其它系统配置。
#
# 幂等：重复运行结果一致。角色已存在时**同步密码**而不是跳过 —— 沿用
# config.json 里的密码为准，避免"库里旧密码 / 配置里新密码"导致的 SASL 认证失败。
#
# 用法：
#   sudo ./scripts/setup-postgres.sh                       # 读 ./config.json
#   sudo ./scripts/setup-postgres.sh --config /opt/pojun/config.json
#   sudo ./scripts/setup-postgres.sh --password 'MyPass123' --no-write-config
#   ./scripts/setup-postgres.sh --dry-run                  # 只打印将要做什么
#
# 选项：
#   --config PATH       配置文件路径（默认依次找 ./config.json、可执行文件同级 config.json）
#   --user NAME         数据库角色名（默认取配置里的 database.user，否则 pojun）
#   --dbname NAME       数据库名（默认取 database.dbname，否则 pojun）
#   --password PASS     指定密码（默认取配置；配置为空则随机生成）
#   --host HOST         写入配置的连接地址（默认取 database.host，否则 127.0.0.1）
#   --port PORT         写入配置的端口（默认取 database.port，否则 5432）
#   --superuser NAME    执行建库建角色用的 PostgreSQL 超级用户（默认 postgres）
#   --no-write-config   不修改 config.json，只把密码打印出来
#   --dry-run           只打印计划，不执行任何写操作
#   -h, --help          显示本帮助

set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
CONFIG=""
DB_USER=""
DB_NAME=""
DB_PASS=""
DB_HOST=""
DB_PORT=""
PG_SUPER="${PG_SUPER:-postgres}"
WRITE_CONFIG=1
DRY_RUN=0

info() { printf '\033[36m[信息]\033[0m %s\n' "$*"; }
ok()   { printf '\033[32m[完成]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[注意]\033[0m %s\n' "$*"; }
die()  { printf '\033[31m[失败]\033[0m %s\n' "$*" >&2; exit 1; }

usage() { sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

while [ $# -gt 0 ]; do
  case "$1" in
    --config)        CONFIG="${2:-}"; shift 2 ;;
    --user)          DB_USER="${2:-}"; shift 2 ;;
    --dbname)        DB_NAME="${2:-}"; shift 2 ;;
    --password)      DB_PASS="${2:-}"; shift 2 ;;
    --host)          DB_HOST="${2:-}"; shift 2 ;;
    --port)          DB_PORT="${2:-}"; shift 2 ;;
    --superuser)     PG_SUPER="${2:-}"; shift 2 ;;
    --no-write-config) WRITE_CONFIG=0; shift ;;
    --dry-run)       DRY_RUN=1; shift ;;
    -h|--help)       usage ;;
    *) die "未知参数：$1（用 --help 查看用法）" ;;
  esac
done

# ---------- 定位配置文件 ----------
if [ -z "$CONFIG" ]; then
  if [ -n "${POJUN_CONFIG:-}" ]; then
    CONFIG="$POJUN_CONFIG"
  elif [ -f "./config.json" ]; then
    CONFIG="./config.json"
  elif [ -f "$(dirname "$0")/../config.json" ]; then
    CONFIG="$(dirname "$0")/../config.json"
  else
    CONFIG="./config.json"
  fi
fi

# ---------- 读取配置字段 ----------
# 优先 python3（保真解析），退化到 grep/sed（够用，但不认复杂转义）。
read_cfg() {
  local key="$1"
  [ -f "$CONFIG" ] || return 0
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$CONFIG" "$key" <<'PY' 2>/dev/null || true
import json,sys
try:
    d=json.load(open(sys.argv[1]))
except Exception:
    sys.exit(0)
db=d.get("database") or {}
if "dsn" in db and db.get("dsn"):
    sys.exit(0)
v=db.get(sys.argv[2])
if v is None:
    sys.exit(0)
print(v)
PY
  else
    sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\"\{0,1\}\([^\",]*\)\"\{0,1\}.*/\1/p" "$CONFIG" | head -1
  fi
}

CONFIG_EXISTS=0
[ -f "$CONFIG" ] && CONFIG_EXISTS=1

if [ "$CONFIG_EXISTS" = "1" ]; then
  [ -z "$DB_USER" ] && DB_USER="$(read_cfg user)"
  [ -z "$DB_NAME" ] && DB_NAME="$(read_cfg dbname)"
  [ -z "$DB_PASS" ] && DB_PASS="$(read_cfg password)"
  [ -z "$DB_HOST" ] && DB_HOST="$(read_cfg host)"
  [ -z "$DB_PORT" ] && DB_PORT="$(read_cfg port)"
  # 配置若用完整 DSN 写法，分字段就不作数了，这里只提示不猜。
  # 注意必须只看 database.dsn 本身：配置文件里常带 "_example_database_dsn" 示例段，
  # 用 grep 匹配 "dsn" 会把示例误判成真实配置。
  cfg_has_dsn() {
    command -v python3 >/dev/null 2>&1 || return 1
    python3 - "$CONFIG" <<'PY'
import json,sys
try:
    d=json.load(open(sys.argv[1]))
except Exception:
    sys.exit(1)
db=d.get("database") or {}
sys.exit(0 if (isinstance(db,dict) and db.get("dsn")) else 1)
PY
  }
  if cfg_has_dsn; then
    die "config.json 使用 database.dsn（完整连接串）：本脚本的分字段建库/回写密码不会影响服务的实际连接，继续执行会造成「配置完成但连不上」的假完成。请手动处理，或把 config.json 改为分字段写法后再运行。"
  fi
else
  info "未找到 $CONFIG，将按默认值新建：user/db=pojun，host=127.0.0.1:5432"
fi

DB_USER="${DB_USER:-pojun}"
DB_NAME="${DB_NAME:-pojun}"
DB_HOST="${DB_HOST:-127.0.0.1}"
DB_PORT="${DB_PORT:-5432}"

# ---------- 密码 ----------
PASS_GENERATED=0
if [ -z "$DB_PASS" ]; then
  DB_PASS="$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24)"
  PASS_GENERATED=1
  info "配置里没有密码，已生成一个：$DB_PASS"
fi

# ---------- 检查前置 ----------
# SQL 标识符/字面量按单引号拼接，值里出现单引号会破坏语句——显式拒绝而不是静默坏掉。
for _v in "$DB_USER" "$DB_NAME"; do
  case "$_v" in *"'"*) die "标识符不能包含单引号：$_v";; esac
done
if [ -n "$DB_PASS" ]; then
  case "$DB_PASS" in *"'"*) die "密码不能包含单引号（请换用不含 ' 的密码）";; esac
fi

command -v psql >/dev/null 2>&1 || die "psql 不在 PATH，请先安装 PostgreSQL 客户端"
if command -v pg_isready >/dev/null 2>&1; then
  pg_isready -h "$DB_HOST" -p "$DB_PORT" >/dev/null 2>&1 \
    || warn "pg_isready 探测 $DB_HOST:$DB_PORT 未就绪，继续尝试（可能是 socket 与 TCP 的区别）"
fi

# 执行超级用户命令：root 下优先 su，普通用户走 sudo
as_super() {
  if [ "$(id -u)" = "0" ]; then
    su "$PG_SUPER" -c "$1"
  else
    sudo -n -u "$PG_SUPER" bash -c "$1" 2>/dev/null || sudo -u "$PG_SUPER" bash -c "$1"
  fi
}

sql_super() { as_super "psql -X -tA -c \"$1\" postgres" | tr -d '[:space:]'; }

info "目标：角色=$DB_USER 库=$DB_NAME 连接=$DB_HOST:$DB_PORT 配置文件=$CONFIG"

if [ "$DRY_RUN" = "1" ]; then
  echo
  info "[dry-run] 将要执行的步骤："
  cat <<EOF
  1. 检查角色 $DB_USER 是否存在（不存在则 CREATE ROLE，存在则 ALTER ROLE 同步密码）
  2. 检查库 $DB_NAME 是否存在（不存在则 CREATE DATABASE ... OWNER $DB_USER ENCODING 'UTF8'）
  3. $([ "$WRITE_CONFIG" = "1" ] && echo "把密码写回 $CONFIG（并留 .bak 备份）" || echo "不回写配置，只打印密码")
  4. 用新建的凭据走 TCP 登录验证
  不改 pg_hba.conf / postgresql.conf / 任何其它系统配置。
EOF
  echo
  exit 0
fi

# ---------- 1. 角色 ----------
role_exists="$(sql_super "SELECT 1 FROM pg_roles WHERE rolname='$DB_USER'")"
if [ "$role_exists" = "1" ]; then
  info "角色 $DB_USER 已存在，同步密码"
  as_super "psql -X -q -v ON_ERROR_STOP=1 -c \"ALTER ROLE \\\"$DB_USER\\\" LOGIN PASSWORD '$DB_PASS'\"" >/dev/null
else
  info "创建角色 $DB_USER"
  as_super "psql -X -q -v ON_ERROR_STOP=1 -c \"CREATE ROLE \\\"$DB_USER\\\" LOGIN PASSWORD '$DB_PASS'\"" >/dev/null
fi
ok "角色 $DB_USER 就绪（LOGIN，非超级用户）"

# ---------- 2. 数据库 ----------
db_row="$(sql_super "SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname='$DB_NAME'")"
if [ -n "$db_row" ]; then
  info "库 $DB_NAME 已存在，属主为 $db_row"
  if [ "$db_row" != "$DB_USER" ]; then
    warn "库属主不是 $DB_USER。为避免影响既有数据，本脚本不自动改属主；如确需更换请手动 ALTER DATABASE。"
  fi
else
  info "创建库 $DB_NAME（属主 $DB_USER，UTF8）"
  as_super "psql -X -q -v ON_ERROR_STOP=1 -c \"CREATE DATABASE \\\"$DB_NAME\\\" OWNER \\\"$DB_USER\\\" ENCODING 'UTF8'\"" >/dev/null
  ok "库 $DB_NAME 已创建"
fi

# public schema 的建表权：PG15+ 库属主经由 pg_database_owner 自动持有，
# PG14 及更早需要在库里显式 GRANT。这里统一补一次，幂等且不影响既有对象。
as_super "psql -X -q -d \"$DB_NAME\" -v ON_ERROR_STOP=1 -c \"GRANT CREATE, USAGE ON SCHEMA public TO \\\"$DB_USER\\\"\"" >/dev/null 2>&1 || true

# ---------- 3. 回写配置 ----------
if [ "$WRITE_CONFIG" = "1" ]; then
  if [ "$CONFIG_EXISTS" = "1" ] && command -v python3 >/dev/null 2>&1; then
    # 已有配置一律做**字段合并**，只改 database 下的键，其余（skill_dir、注释字段、
    # 任何后续新增配置）原样保留。历史上"整份重写"会把别人的 skill_dir 抹掉。
    cp -a "$CONFIG" "$CONFIG.bak"
    python3 - "$CONFIG" "$DB_PASS" "$DB_USER" "$DB_NAME" "$DB_HOST" "$DB_PORT" <<'PY'
import json,sys
p,pw,u,db,h,po=sys.argv[1:7]
with open(p,encoding="utf-8") as f:
    d=json.load(f)
d.setdefault("database",{})
d["database"]["password"]=pw
d["database"]["user"]=u
d["database"]["dbname"]=db
d["database"]["host"]=h
d["database"]["port"]=int(po)
with open(p,"w",encoding="utf-8") as f:
    json.dump(d,f,ensure_ascii=False,indent=2)
    f.write("\n")
PY
    chmod 600 "$CONFIG"
    ok "已合并写入 $CONFIG（备份：$CONFIG.bak，权限 600）"
  elif [ "$CONFIG_EXISTS" = "1" ]; then
    warn "没有 python3，改写 JSON 会破坏原有字段，故不自动修改 $CONFIG。请手动把 database.password 填为：$DB_PASS"
  else
    cat > "$CONFIG" <<JSON
{
  "database": {
    "host": "$DB_HOST",
    "port": $DB_PORT,
    "user": "$DB_USER",
    "password": "$DB_PASS",
    "dbname": "$DB_NAME",
    "sslmode": "disable"
  }
}
JSON
    chmod 600 "$CONFIG"
    ok "已新建 $CONFIG（权限 600）"
  fi
else
  warn "按 --no-write-config 未修改配置。密码：$DB_PASS"
fi

# ---------- 4. 登录验证 ----------
info "验证 TCP 登录..."
if PGPASSWORD="$DB_PASS" psql -X -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
     -tAc "SELECT current_user || '@' || current_database()" >/dev/null 2>&1; then
  ok "连接验证通过：$DB_USER@$DB_NAME（$DB_HOST:$DB_PORT）"
else
  echo
  die "连接验证失败。常见原因：
  · pg_hba.conf 对 $DB_HOST 的认证方式不是 scram-sha-256/md5/trust —— 本脚本不会改这个文件，请自行确认；
  · 配置里的 host 是 unix socket 路径而非 IP，需改用 local peer 认证；
  · 数据库尚未接受连接（service 未重启）。
  排查命令：sudo -u $PG_SUPER psql -c \"select rolname from pg_roles where rolname='$DB_USER'\""
fi

if [ "$PASS_GENERATED" = "1" ]; then
  echo
  ok "配置完成。新生成的密码：$DB_PASS（已写入 $CONFIG）"
else
  echo
  ok "配置完成。"
fi
