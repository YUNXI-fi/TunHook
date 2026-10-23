#!/bin/bash
#
# TunHook 开发迭代脚本：前端构建 → 重建二进制 → 重启本机正在运行的实例
#
# 目录约定（源码/运行数据/打包目录分离）：
#   src/       Go 源码与前端工程（本脚本所在仓库根下）
#   dev-data/  开发运行时数据，二进制也输出到这里（dataDir 由可执行文件目录推导）
#   TunHook/   仅打包内容，不存放二进制与运行数据
#
# 为什么必须三步（缺一步界面就不会更新）：
#   1) 前端产物 src/web/static 由 //go:embed 在「编译期」嵌入二进制，只跑 vite build 不会影响运行中的进程；
#   2) go build ./... 只做编译检查、不产出二进制，必须 go build -o ../tunhook . 才真正更新可执行文件；
#   3) 运行中的进程仍持有旧二进制，必须重启才会加载新界面。
#
# 用法：./dev-restart.sh
#   - 未检测到正在运行的实例时只构建，并提示手动启动；
#   - 重启沿用该实例原有的工作目录、命令行参数与 TUNHOOK_*/TRIM_* 环境变量（不硬编码端口与数据目录）；
#   - 注意：实例若原本在你自己的终端前台运行，重启后其前台命令会结束，新进程以后台方式运行。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="${SCRIPT_DIR}/src"
UI_DIR="${SRC_DIR}/web/ui"
DATA_DIR="${SCRIPT_DIR}/dev-data"
BIN="${DATA_DIR}/tunhook"
BIN_NAME="$(basename "${BIN}")"

# same_bin 判断 PID 是否运行着目标二进制。
# 二进制已被替换时 /proc/<pid>/exe 会带 " (deleted)" 后缀，需要先剥掉再比较。
same_bin() {
  local exe
  exe="$(readlink "/proc/$1/exe" 2>/dev/null || true)"
  [ "${exe% (deleted)}" = "${BIN}" ]
}

# ---------- 0. 先记录正在运行的实例 ----------
# 必须在替换二进制之前取，替换后 /proc/<pid>/exe 会变成 "<路径> (deleted)"，无法再按路径辨认。
RUNNING_PIDS=()
mapfile -t CANDIDATES < <(pgrep -x "${BIN_NAME}" || true)
for pid in "${CANDIDATES[@]}"; do
  same_bin "${pid}" || continue
  RUNNING_PIDS+=("${pid}")
done

# ---------- 1. 前端构建（产物输出到 src/web/static） ----------
echo "[dev-restart] 构建前端…"
cd "${UI_DIR}"
if [ -x node_modules/.bin/vite ]; then
  node_modules/.bin/vite build
else
  # node_modules/.bin 缺失时直接用 node 执行 vite（此环境下 npm run 会报 vite: not found）
  node node_modules/vite/bin/vite.js build
fi

# ---------- 2. 重建二进制 ----------
# 先构建到临时文件再改名替换：直接覆盖正在运行的二进制会报 text file busy。
echo "[dev-restart] 重建二进制…"
cd "${SRC_DIR}"
TMP_BIN="$(mktemp "${TMPDIR:-/tmp}/tunhook-build.XXXXXX")"
trap 'rm -f "${TMP_BIN}"' EXIT
go build -o "${TMP_BIN}" .
chmod 755 "${TMP_BIN}"
mv -f "${TMP_BIN}" "${BIN}"

# ---------- 3. 重启实例 ----------
if [ "${#RUNNING_PIDS[@]}" -eq 0 ]; then
  echo "[dev-restart] 未检测到正在运行的实例：二进制已更新（${BIN}），下次启动即为新界面"
  exit 0
fi

for pid in "${RUNNING_PIDS[@]}"; do
  # 记录原实例的工作目录、启动参数与配置类环境变量，重启时原样复用
  CWD="$(readlink "/proc/${pid}/cwd" 2>/dev/null || echo /tmp)"
  mapfile -d '' -t ARGV < "/proc/${pid}/cmdline"
  APP_ENVS=()
  while IFS= read -r -d '' kv; do
    case "${kv}" in
      # 只透传 TunHook 自己的配置类变量；PATH/HOME/LANG 等由当前 shell 继承
      TUNHOOK_* | TRIM_*) APP_ENVS+=("${kv}");;
    esac
  done < "/proc/${pid}/environ"
  INSTANCE_DATA_DIR=""
  for kv in "${APP_ENVS[@]}"; do
    case "${kv}" in TUNHOOK_DATA_DIR=*) INSTANCE_DATA_DIR="${kv#TUNHOOK_DATA_DIR=}";; esac
  done
  LOG="${INSTANCE_DATA_DIR:-${DATA_DIR}}/tunhook-dev.log"

  echo "[dev-restart] 停止实例 ${pid}（${ARGV[*]:1}）…"
  kill -TERM "${pid}"
  for _ in $(seq 1 20); do
    kill -0 "${pid}" 2>/dev/null || break
    sleep 0.5
  done
  if kill -0 "${pid}" 2>/dev/null; then
    echo "[dev-restart] 实例 ${pid} 未在 10 秒内退出，已跳过重启，请手动重启" >&2
    continue
  fi

  echo "[dev-restart] 以原配置重新启动，输出 → ${LOG}"
  cd "${CWD}" 2>/dev/null || cd /tmp
  setsid nohup env "${APP_ENVS[@]}" "${BIN}" "${ARGV[@]:1}" >>"${LOG}" 2>&1 </dev/null &

  sleep 2
  # 按二进制路径过滤：机器上可能存在其他同名进程（如 go run 出来的临时二进制），
  # 不过滤会把它们的 PID 当成本次重启结果报出来。
  NEW_PIDS=()
  while IFS= read -r p; do
    same_bin "${p}" || continue
    NEW_PIDS+=("${p}")
  done < <(pgrep -x "${BIN_NAME}" || true)
  if [ "${#NEW_PIDS[@]}" -gt 0 ]; then
    echo "[dev-restart] 完成，实例 PID=${NEW_PIDS[0]}"
  else
    echo "[dev-restart] 启动后未检测到进程，请查看日志：${LOG}" >&2
    exit 1
  fi
done
