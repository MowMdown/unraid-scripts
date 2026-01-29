#!/usr/bin/env bash
set -uo pipefail
SRC_ROOT="/mnt/disk1/data/torrents"
DST_ROOT="/mnt/disk1/data/media"
USR_POOL="cache"
HASH_CACHE="/mnt/user/appdata/hardlinks.txt"
DRY_RUN="yes"
REPORT_EVERY=250
VERBOSE="yes"
DEBUG="yes"
MAX_PARALLEL_DISKS=4
SRC_REL_PATH="${SRC_ROOT#/mnt/user/}"
COUNTER_DIR="hardlink_counters.$$"
HARDLINK_LOCK="/tmp/hardlinker/hardlink.lock"
HASH_LOCK="/tmp/hardlinker/hash_cache.lock"
mkdir -p "/tmp/hardlinker/$COUNTER_DIR"
declare -A torrent_by_size_disk
declare -A hash_cache
declare -A file_metadata
scanned_src=0
log() { [[ "$VERBOSE" == "yes" ]] && echo "[LOG] $*" >&2; }
info() { echo "[INFO] $*"; }
debug() { [[ "$DEBUG" == "yes" ]] && echo "[DEBUG] $*" >&2; }
warn() { echo "[WARN] $*" >&2; }
get_disk_id() {
    local path="$1"
    if [[ "$path" =~ ^/mnt/(disk[0-9]+|[^/]+)/ ]]; then
        echo "${BASH_REMATCH[1]}"
    else
        echo "unknown"
    fi
}
get_hash() {
    local file="$1"
    local size="$2"
    local mtime
    mtime=$(stat -c '%Y' -- "$file")
    local key="$file|$size|$mtime"
    if [[ -n "${hash_cache[$key]:-}" ]]; then
        echo "${hash_cache[$key]}"
        return
    fi
    info "Computing hash for: $file"
    log "Hash needed for: $file (size=$size mtime=$mtime)"
    local hash
    hash=$(sha256sum -- "$file" | awk '{print $1}')
    hash_cache["$key"]="$hash"
    {
        exec 8>"$HASH_LOCK"
        flock 8
        echo "${size}|${mtime}|${hash}|${file}" >> "$HASH_CACHE"
        flock -u 8
    } 8>&-
    echo "$hash"
}
load_hash_cache() {
    if [[ -f "$HASH_CACHE" ]]; then
        info "Loading hash cache from: $HASH_CACHE"
        local count=0
        while IFS='|' read -r size mtime hash path; do
            hash_cache["${path}|${size}|${mtime}"]="$hash"
            ((count++))
        done < "$HASH_CACHE"
        info "Loaded $count cached hashes"
    fi
}
resolve_scan_paths() {
    local root="$1"
    local -n out_paths=$2
    out_paths=()
    log "Resolving scan paths for: $root"
    if [[ "$root" =~ ^/mnt/user/ ]]; then
        log "User share detected, expanding to physical disks and pools"
        for disk_path in /mnt/disk*; do
            [[ -d "$disk_path" ]] || continue
            log "Adding disk path: $disk_path/${root#/mnt/user/}"
            out_paths+=("$disk_path/${root#/mnt/user/}")
        done
        for pool in $USR_POOL; do
            [[ -d "/mnt/${pool}" ]] || continue
            log "Adding pool path: /mnt/${pool}/${root#/mnt/user/}"
            out_paths+=("/mnt/${pool}/${root#/mnt/user/}")
        done
    else
        log "Physical path detected, using directly: $root"
        out_paths+=("$root")
    fi
    log "Resolved ${#out_paths[@]} scan paths for: $root"
}
index_source_files() {
    info "Indexing source files from: $SRC_ROOT"
    local scan_paths=()
    resolve_scan_paths "$SRC_ROOT" scan_paths
    local found_dirs=0
    for dir in "${scan_paths[@]}"; do
        [[ -d "$dir" ]] && ((found_dirs++))
    done
    [[ $found_dirs -eq 0 ]] && { warn "No source directories found"; return 1; }
    debug "Found $found_dirs source directories"
    for dir in "${scan_paths[@]}"; do
        [[ ! -d "$dir" ]] && continue
        debug "Scanning: $dir"
        while IFS= read -r -d '' phys_path; do
            log "Torrent being indexed: $phys_path"
            local size inode disk_id
            size=$(stat -c '%s' -- "$phys_path")
            inode=$(stat -c '%i' -- "$phys_path")
            disk_id=$(get_disk_id "$phys_path")
            local key="${size}|${disk_id}"
            torrent_by_size_disk["$key"]+="${phys_path}|"
            file_metadata["$phys_path"]="${inode}|${size}|${disk_id}"
            ((scanned_src++))
            (( scanned_src % REPORT_EVERY == 0 )) && info "Indexed $scanned_src source files"
        done < <(find "$dir" -type f -name '*.mkv' -print0 2>/dev/null)
    done
    [[ $scanned_src -eq 0 ]] && { warn "No source files found"; return 1; }
    info "Indexed $scanned_src source files"
}
scan_disk() {
    local disk_path="$1"
    info "Scanning: $disk_path"
    while IFS= read -r -d '' dst_phys_path; do
        [[ "$dst_phys_path" == /mnt/*/"$SRC_REL_PATH"/* ]] && { log "Skipping source path during destination scan: $dst_phys_path"; continue; }
        log "File being scanned: $dst_phys_path"
        echo 1 >> "/tmp/hardlinker/$COUNTER_DIR/scanned_dst"
        [[ ! -f "$dst_phys_path" ]] && continue
        local dst_size dst_inode dst_disk
        dst_size=$(stat -c '%s' -- "$dst_phys_path")
        dst_inode=$(stat -c '%i' -- "$dst_phys_path")
        dst_disk=$(get_disk_id "$dst_phys_path")
        local same_disk_key="${dst_size}|${dst_disk}"
        [[ -n "${torrent_by_size_disk[$same_disk_key]:-}" ]] &&
            try_match_candidates "$dst_phys_path" "$dst_phys_path" "$dst_size" "$dst_inode" "$dst_disk" "${torrent_by_size_disk[$same_disk_key]}" "same-disk"
        for key in "${!torrent_by_size_disk[@]}"; do
            IFS='|' read -r size disk <<< "$key"
            [[ "$size" != "$dst_size" ]] && continue
            [[ "$disk" == "$dst_disk" ]] && continue
            try_match_candidates "$dst_phys_path" "$dst_phys_path" "$dst_size" "$dst_inode" "$dst_disk" "${torrent_by_size_disk[$key]}" "cross-disk"
        done
    done < <(find "$disk_path" -type f -name '*.mkv' -print0 2>/dev/null)
}
process_destination_files() {
    info "Processing destination files from: $DST_ROOT"
    local scan_paths=()
    resolve_scan_paths "$DST_ROOT" scan_paths
    local found_dirs=0
    for dir in "${scan_paths[@]}"; do
        [[ -d "$dir" ]] && ((found_dirs++))
    done
    [[ $found_dirs -eq 0 ]] && { warn "No destination directories found"; return 1; }
    debug "Found $found_dirs destination directories"
    if (( MAX_PARALLEL_DISKS == 0 )); then
        CPU_CORES=$(nproc)
        DISK_COUNT=$(ls -d /mnt/disk* 2>/dev/null | wc -l)
        MAX_PARALLEL_DISKS=$(( CPU_CORES < DISK_COUNT ? CPU_CORES : DISK_COUNT ))
        (( MAX_PARALLEL_DISKS < 1 )) && MAX_PARALLEL_DISKS=1
    fi
    local active_jobs=0
    for disk_path in "${scan_paths[@]}"; do
        [[ ! -d "$disk_path" ]] && continue
        ( scan_disk "$disk_path" ) &
        ((active_jobs++))
        (( active_jobs >= MAX_PARALLEL_DISKS )) && { wait -n; ((active_jobs--)); }
    done
    wait
}
try_match_candidates() {
    local dst_user_path="$1"
    local dst_phys_path="$2"
    local dst_size="$3"
    local dst_inode="$4"
    local dst_disk="$5"
    local candidates_str="$6"
    local match_type="$7"
    IFS='|' read -ra candidates <<< "$candidates_str"
    for src_path in "${candidates[@]}"; do
        [[ -z "$src_path" ]] && continue
        local src_metadata="${file_metadata[$src_path]}"
        IFS='|' read -r src_inode src_size src_disk <<< "$src_metadata"
        [[ "$src_inode" == "$dst_inode" ]] && continue
        if cmp -s -- "$src_path" "$dst_phys_path"; then
            if (( ${#candidates[@]} > 1 )); then
                src_hash=$(get_hash "$src_path" "$src_size")
                dst_hash=$(get_hash "$dst_phys_path" "$dst_size")
                if [[ "$src_hash" != "$dst_hash" ]]; then
                    log "HASH COLLISION DETECTED"
                    log "$src_path => $src_hash"
                    log "$dst_phys_path => $dst_hash"
                    continue
                fi
            fi
            create_hardlink "$dst_phys_path" "$dst_phys_path" "$src_path" "$src_disk" "$match_type"
            return 0
        fi
    done
    return 1
}
create_hardlink() {
    exec 9>"$HARDLINK_LOCK"
    flock 9
    local dst_user_path="$1"
    local dst_phys_path="$2"
    local src_path="$3"
    local src_disk="$4"
    local match_type="$5"
    echo 1 >> "/tmp/hardlinker/$COUNTER_DIR/matches"
    local dst_disk rel_path target_phys_path
    dst_disk=$(get_disk_id "$dst_phys_path")
    rel_path="${dst_phys_path#/mnt/${dst_disk}/}"
    target_phys_path="/mnt/${src_disk}/${rel_path}"
    target_phys_path=$(echo "$target_phys_path" | sed 's|//|/|g')
    info "=========================================="
    info "MATCH ($match_type): $(basename "$dst_phys_path") -> $src_disk"
    info "  Source: $src_path"
    info "  Target: $target_phys_path"
    [[ "$DRY_RUN" == "yes" ]] && { info "  [DRY RUN]"; flock -u 9; return; }
    [[ ! -f "$src_path" ]] && { warn "Source missing: $src_path"; flock -u 9; return; }
    mkdir -p -- "$(dirname -- "$target_phys_path")"
    local temp_link="${target_phys_path}.hardlink.tmp"
    local backup_path="${dst_phys_path}.DUPLICATE"
    if ln -- "$src_path" "$temp_link" 2>/dev/null; then
        mv -- "$dst_phys_path" "$backup_path"
        mv -- "$temp_link" "$target_phys_path"
        info "  ✓ Hardlink created, old file renamed to: $backup_path"
        info "=========================================="
    else
        warn "Failed: $dst_phys_path"
        [[ -f "$temp_link" ]] && rm -f -- "$temp_link"
    fi
    flock -u 9
}
main() {
    info "=========================================="
    info "  Unraid Hardlink Optimizer"
    info "  Source: $SRC_ROOT"
    info "  Destination: $DST_ROOT"
    info "  Dry Run: $DRY_RUN"
    info "=========================================="
    load_hash_cache
    index_source_files || { warn "Failed to index sources"; exit 1; }
    process_destination_files
    scanned_dst=$(wc -l < "/tmp/hardlinker/$COUNTER_DIR/scanned_dst" 2>/dev/null || echo 0)
    matches=$(wc -l < "/tmp/hardlinker/$COUNTER_DIR/matches" 2>/dev/null || echo 0)
    rm -r /tmp/hardlinker/*
    info "=========================================="
    info "  Complete!"
    info "  Source files indexed: $scanned_src"
    info "  Destination files scanned: $scanned_dst"
    info "  Matches found: $matches"
    info "=========================================="
}
main "$@"
