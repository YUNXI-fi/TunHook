#!/bin/bash
#
# TunHook fnOS 打包脚本
#
# 目录约定（源码与打包目录分离）：
#   TunHook/   本脚本所在目录，只放打包内容（manifest/app/cmd/config/wizard/i18n/图标）
#   ../src/    Go 源码（前端构建产物 src/web/static 已由 go:embed 嵌入）
#   ../dev-data/  开发运行时数据（数据库/日志/frp 客户端等），不参与打包
#
# 流程：校验 → 从 src 构建二进制 → 临时移走重复资源 → fnpack build → 输出到「编译产物」
# 用法：./build.sh
#
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
SRC_DIR="${REPO_DIR}/src"

# ---------- 读取 manifest ----------
APPNAME="$(grep -m1 '^appname=' manifest | cut -d= -f2)"
VERSION="$(grep -m1 '^version=' manifest | cut -d= -f2)"
if [ -z "${APPNAME}" ] || [ -z "${VERSION}" ]; then
  echo "[错误] 无法从 manifest 读取 appname/version" >&2
  exit 1
fi
OUT_FILE="${APPNAME}_v${VERSION}.fpk"
# 历史安装包统一存放在仓库根的「编译产物」目录，与项目目录分离：
# fnpack 会在 SCRIPT_DIR 下生成 .fpk，项目目录内不留产物目录，历史版本自然累积不被覆盖。
# 可用 TUNHOOK_ARTIFACT_DIR 覆盖（如需输出到别处或做 CI 归档）。
OUT_DIR="${TUNHOOK_ARTIFACT_DIR:-${REPO_DIR}/编译产物}"

# ---------- 前置检查 ----------
if ! command -v fnpack >/dev/null 2>&1; then
  echo "[错误] 未找到 fnpack，请先安装（https://developer.fnnas.com）" >&2
  exit 1
fi
if ! command -v go >/dev/null 2>&1; then
  echo "[错误] 未找到 go，无法从 ${SRC_DIR} 构建二进制" >&2
  exit 1
fi
if [ ! -f "${SRC_DIR}/go.mod" ]; then
  echo "[错误] 未找到源码目录: ${SRC_DIR}（打包目录应与 src/ 平级）" >&2
  exit 1
fi
if [ ! -f "${SRC_DIR}/web/static/index.html" ]; then
  echo "[错误] 未找到前端构建产物: ${SRC_DIR}/web/static（请先执行 cd src/web/ui && npm run build）" >&2
  exit 1
fi

# ---------- 构建二进制 ----------
# 二进制属于构建产物，不进源码目录：先构建到临时目录，打包时复制进 app/。
# 前端资源需先构建：cd ../src/web/ui && npm run build（产物 src/web/static 由 go:embed 嵌入）。
BUILD_DIR="$(mktemp -d)"
BUILD_BIN="${BUILD_DIR}/tunhook"
echo "[TunHook] go build（${SRC_DIR}）..."
(cd "${SRC_DIR}" && go build -o "${BUILD_BIN}" .)

# ---------- 不入包的开发数据（打包完成后恢复） ----------
# app/frp 下的 frpc 配置/日志/测试证书为开发环境数据，不应进入安装包；
# app/frp/packages 为运行时留档目录（frpc 安装后由程序在 @appdata/frp/packages 自建），
# 与 app/frp 根级的内置安装包重复，不入包（省约 14MB）。
PKG_EXCLUDE_PATHS=(
  "app/frp/frpc.json"
  "app/frp/frpc.toml"
  "app/frp/frpc.log"
  "app/frp/certs"
  "app/frp/packages"
)
STAGE_DIR="$(mktemp -d)"

restore_package_data() {
  local code=$?
  # 移除打包时复制进 app/ 的应用二进制副本（构建产物，非项目文件）
  rm -f "${SCRIPT_DIR}/app/tunhook"
  # fnpack 生成的临时 .fpk（已移出到产物目录），避免留在项目目录
  rm -f "${SCRIPT_DIR}/${APPNAME}.fpk"
  rm -rf "${BUILD_DIR}"
  if [ -d "${STAGE_DIR}" ]; then
    for rel in "${PKG_EXCLUDE_PATHS[@]}"; do
      if [ -e "${STAGE_DIR}/${rel}" ]; then
        mkdir -p "$(dirname "${SCRIPT_DIR}/${rel}")"
        mv -f "${STAGE_DIR}/${rel}" "${SCRIPT_DIR}/${rel}"
      fi
    done
    rm -rf "${STAGE_DIR}"
  fi
  return $code
}
trap restore_package_data EXIT

for rel in "${PKG_EXCLUDE_PATHS[@]}"; do
  if [ -e "${SCRIPT_DIR}/${rel}" ]; then
    mkdir -p "$(dirname "${STAGE_DIR}/${rel}")"
    mv "${SCRIPT_DIR}/${rel}" "${STAGE_DIR}/${rel}"
  fi
done
echo "[TunHook] 已暂存 app/frp 开发数据与重复资源（打包完成后自动恢复）"

# ---------- 复制应用二进制到 app/ ----------
# fnpack 只打包 app/、cmd/、config/、wizard/ 等固定顶层条目，根目录的可执行文件
# 不会进入安装包；安装后 app/ 目录对应 target/（TRIM_APPDEST），放入 app/ 的
# tunhook 会分发到 $TRIM_APPDEST/tunhook（cmd 脚本按此路径引用）。
cp -f "${BUILD_BIN}" app/tunhook
chmod 755 app/tunhook
echo "[TunHook] 已复制应用二进制到 app/tunhook"

# ---------- 打包 ----------
echo "[TunHook] fnpack build ..."
fnpack build --directory "${SCRIPT_DIR}" > /dev/null

if [ ! -f "${SCRIPT_DIR}/${APPNAME}.fpk" ]; then
  echo "[错误] 打包失败，未生成 ${APPNAME}.fpk" >&2
  exit 1
fi

# ---------- 重命名并输出 ----------
# 历史版本累积保留：同名（版本号未变）时覆盖前先提示，避免误以为产出了新版本
mkdir -p "${OUT_DIR}"
if [ -f "${OUT_DIR}/${OUT_FILE}" ]; then
  echo "[TunHook] 提示: ${OUT_FILE} 已存在（版本号未变），将覆盖"
fi
mv -f "${SCRIPT_DIR}/${APPNAME}.fpk" "${OUT_DIR}/${OUT_FILE}"
echo "[TunHook] 安装包: ${OUT_DIR}/${OUT_FILE}"
echo "[TunHook] 该目录现有安装包 $(find "${OUT_DIR}" -maxdepth 1 -name "${APPNAME}_v*.fpk" | wc -l) 个"

# ---------- 输出校验 ----------
tar -tzf "${OUT_DIR}/${OUT_FILE}" > /dev/null 2>&1 && echo "[TunHook] 包结构校验通过"
echo "[TunHook] 打包完成"
