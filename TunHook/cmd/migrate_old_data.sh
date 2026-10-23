#!/bin/bash
# TunHook 安装/升级预处理共用的旧数据迁移逻辑。
# 把旧版本可能存放运行数据/配置的位置并入 @appdata（运行数据）与 @appconf（配置），
# 避免替换应用目录 / 重建共享目录导致旧数据丢失。
# 由 cmd/install_init、cmd/upgrade_init source 后调用 migrate_old_data。
# 幂等：目标已存在则跳过（不覆盖），已有数据一律复用，绝不新建覆盖。

# 目录推导：优先 TRIM_PKGVAR/TRIM_PKGETC；fnOS 下缺失时按标准布局推导
# /vol{n}/@appdata/TunHook 与 /vol{n}/@appconf/TunHook，绝不回退到应用目录
# （@appcenter/TunHook 会被升级替换，数据迁移到这里等于白迁）。
_derive_persist_dir() {
    local var_name="$1" sub="$2" v
    v="$(eval "printf '%s' \"\$$var_name\"")"
    if [ -n "$v" ]; then
        printf '%s' "$v"
        return 0
    fi
    if [ -n "$TRIM_APPDEST_VOL" ]; then
        printf '%s/%s/TunHook' "$TRIM_APPDEST_VOL" "$sub"
        return 0
    fi
    case "$TRIM_APPDEST" in
        */@appcenter/*)
            printf '%s/%s/TunHook' "${TRIM_APPDEST%/@appcenter/*}" "$sub"
            return 0 ;;
    esac
    # 标准布局推导（/vol{n}/@appdata 等）：从应用目录路径反推卷根（首个路径段）
    if [ -n "$TRIM_APPDEST" ]; then
        local vol
        vol="$(printf '%s' "$TRIM_APPDEST" | cut -d/ -f2)"
        [ -n "$vol" ] && printf '/%s/%s/TunHook' "$vol" "$sub" && return 0
    fi
    printf '%s' "$TRIM_APPDEST"
}

# move_keep 迁移单个目录/文件：源不存在跳过；目标已存在非空内容时跳过（复用已有数据，不覆盖）。
move_keep() {
    local src="$1" dst="$2" name="$3"
    [ -e "$src" ] || return 0
    # 目标已存在（目录非空或文件）→ 复用已有数据，跳过迁移
    if [ -e "$dst" ]; then
        if [ -d "$dst" ] && [ -z "$(ls -A "$dst" 2>/dev/null)" ]; then
            rmdir "$dst" 2>/dev/null || true
        else
            echo "已检测到 ${name}，复用现有数据（$dst），跳过迁移"
            return 0
        fi
    fi
    mkdir -p "$(dirname "$dst")"
    if mv -f "$src" "$dst" 2>/dev/null; then
        echo "已迁移 ${name}: $src -> $dst"
    else
        cp -a "$src" "$dst" 2>/dev/null && echo "已复制 ${name}: $src -> $dst" || true
    fi
}

migrate_old_data() {
    local DATA_DIR ETC_DIR
    DATA_DIR="$(_derive_persist_dir TRIM_PKGVAR @appdata)"
    ETC_DIR="$(_derive_persist_dir TRIM_PKGETC @appconf)"
    mkdir -p "$DATA_DIR" "$ETC_DIR"

    # 数据根自检测：@appdata 已有数据库、@appconf 已有配置 → 上一版本数据已在原地
    # （如卸载「保留数据」后重装、或升级时系统保留持久目录）。不直接 return，
    # 因为 move_keep 已经内置「目标已存在则跳过」的幂等保护，继续遍历 CANDIDATES
    # 可以补迁任何仍留在旧位置的残余数据（如上次迁移时只迁了 db+cfg，没迁 frp）。
    local HAS_DB=false HAS_CFG=false
    [ -f "$DATA_DIR/db/tunhook.db" ] || [ -f "$DATA_DIR/tunhook.db" ] && HAS_DB=true
    [ -f "$ETC_DIR/config.yaml" ] || [ -f "$ETC_DIR/frpc.json" ] || [ -f "$ETC_DIR/frpc.toml" ] && HAS_CFG=true
    if [ "$HAS_DB" = "true" ] && [ "$HAS_CFG" = "true" ]; then
        echo "检测到上一版本数据已存在（数据库与配置齐全），继续扫描旧位置补迁残余数据"
    fi

    # 候选旧数据根：
    # 1) data-share 共享路径本身（旧版可能把运行数据直接放共享根，如 .../tunhook）
    # 2) 共享路径的上级（新版共享路径形如 .../tunhook/log，其上级即旧数据根 .../tunhook）
    # 3) @appdata/data（旧版 TRIM_PKGVAR/data 布局）
    # 4) 应用目录（旧版曾把运行数据放在 target 下；安装/升级前 target 仍为旧包）
    local CANDIDATES=()
    local sp
    local IFS_OLD="$IFS"
    IFS=':' read -ra SHARE_PATHS <<< "${TRIM_DATA_SHARE_PATHS:-}"
    for sp in "${SHARE_PATHS[@]}"; do
        [ -n "$sp" ] || continue
        CANDIDATES+=("$sp")
        if [ "$(basename "$sp")" = "log" ]; then
            CANDIDATES+=("$(dirname "$sp")")
        fi
    done
    IFS="$IFS_OLD"
    CANDIDATES+=("$DATA_DIR/data" "$TRIM_APPDEST/data" "$TRIM_APPDEST")

    local DATA_SUBS="db frp geoloc icons desk-apps rules"
    local DB_FILES="tunhook.db tunhook.db-wal tunhook.db-shm"
    local CFG_FILES="config.yaml frpc.json frpc.toml"
    local src d f

    for src in "${CANDIDATES[@]}"; do
        [ -n "$src" ] && [ -d "$src" ] || continue

        # 1) 运行数据目录并入 @appdata（目标已存在则复用跳过，不覆盖）
        for d in $DATA_SUBS; do
            [ -e "$src/$d" ] || continue
            move_keep "$src/$d" "$DATA_DIR/$d" "数据目录 $d"
        done

        # 2) 数据库文件并入 @appdata/db（move_keep 自带幂等保护，目标已存在则跳过）
        mkdir -p "$DATA_DIR/db"
        for f in $DB_FILES; do
            [ -e "$src/$f" ] || continue
            move_keep "$src/$f" "$DATA_DIR/db/$f" "数据库文件 $f"
        done

        # 3) 配置文件并入 @appconf（目标已存在则复用跳过）
        for f in $CFG_FILES; do
            [ -e "$src/$f" ] || continue
            move_keep "$src/$f" "$ETC_DIR/$f" "配置文件 $f"
        done
    done
}
