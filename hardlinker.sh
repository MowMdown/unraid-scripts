#!/usr/bin/env bash
set -uo pipefail

# Unraid Hardlink Detection & Linking Script (Modular Version)

SRC_ROOT="/mnt/user/data/torrents"
DST_ROOT="/mnt/user/data/media"
USR_POOL="cache"
HASH_CACHE="/mnt/user/appdata/hardlinks.txt"
DRY_RUN="yes"
REPORT_EVERY=250
VERBOSE="no"
DEBUG="yes"

declare -A hash_cache
declare -A file_index  # file_path -> "inode|size|disk"
declare -A size_disk_index  # "size|disk" -> "path1|path2|path3|..."

scanned_src=0
scanned_dst=0
matches=0

# LOGGING FUNCTIONS
log() { [[ "$VERBOSE" == "yes" ]] && echo "[LOG] $*" >&2; }
info() { echo "[INFO] $*"; }
debug() { [[ "$DEBUG" == "yes" ]] && echo "[DEBUG] $*" >&2; }
warn() { echo "[WARN] $*" >&2; }

# UTILITY FUNCTIONS
get_disk_id() {
    local path="$1"
    if [[ "$path" =~ ^/mnt/(disk[0-9]+|[^/]+)/ ]]; then
        echo "${BASH_REMATCH[1]}"
    else
        echo "unknown"
    fi
}

get_file_metadata() {
    local file="$1"
    local size inode disk_id
    size=$(stat -c '%s' -- "$file")
    inode=$(stat -c '%i' -- "$file")
    disk_id=$(get_disk_id "$file")
    echo "${inode}|${size}|${disk_id}"
}

resolve_scan_paths() {
    local root="$1"
    local -n out_paths=$2
    out_paths=()

    if [[ "$root" =~ ^/mnt/user/ ]]; then
        for disk_num in {1..30}; do
            out_paths+=("/mnt/disk${disk_num}/${root#/mnt/user/}")
        done
        for pool in $USR_POOL; do
            out_paths+=("/mnt/${pool}/${root#/mnt/user/}")
        done
    else
        out_paths+=("$root")
    fi
}

# HASH CACHE FUNCTIONS
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
    local hash
    hash=$(sha256sum -- "$file" | awk '{print $1}')
    hash_cache["$key"]="$hash"
    echo "${size}|${mtime}|${hash}|${file}" >> "$HASH_CACHE"
    echo "$hash"
}

# FILE INDEXING FUNCTIONS
index_files() {
    local root="$1"
    local pattern="$2"
    local -n counter=$3
    local -n index_map=$4
    local -n lookup_map=$5

    info "Indexing files from: $root (pattern: $pattern)"

    local scan_paths=()
    resolve_scan_paths "$root" scan_paths

    local found_dirs=0
    for dir in "${scan_paths[@]}"; do
        [[ -d "$dir" ]] && ((found_dirs++))
    done
    
    if [[ $found_dirs -eq 0 ]]; then
        warn "No directories found for: $root"
        return 1
    fi
    
    debug "Found $found_dirs directories to scan"

    for dir in "${scan_paths[@]}"; do
        [[ ! -d "$dir" ]] && continue
        debug "Scanning: $dir"

        while IFS= read -r -d '' file_path; do
            local metadata
            metadata=$(get_file_metadata "$file_path")
            IFS='|' read -r inode size disk_id <<< "$metadata"

            # Store metadata
            index_map["$file_path"]="$metadata"

            # Add to lookup by size+disk
            local key="${size}|${disk_id}"
            lookup_map["$key"]+="${file_path}|"

            ((counter++))
            (( counter % REPORT_EVERY == 0 )) && info "Indexed $counter files"
        done < <(find "$dir" -type f -name "$pattern" -print0 2>/dev/null)
    done

    [[ $counter -eq 0 ]] && { warn "No files found"; return 1; }
    info "Indexed $counter files"
}

# MATCHING FUNCTIONS
find_all_matches() {
    local target_file="$1"
    local target_metadata="$2"
    local -n source_index=$3
    local -n source_lookup=$4
    local -n matches_out=$5

    IFS='|' read -r target_inode target_size target_disk <<< "$target_metadata"
    matches_out=()

    # Check same disk first
    local same_disk_key="${target_size}|${target_disk}"
    if [[ -n "${source_lookup[$same_disk_key]:-}" ]]; then
        find_matches_in_candidates "$target_file" "$target_metadata" "${source_lookup[$same_disk_key]}" source_index matches_out "same-disk"
    fi

    # Check cross-disk
    for key in "${!source_lookup[@]}"; do
        IFS='|' read -r size disk <<< "$key"
        [[ "$size" != "$target_size" ]] && continue
        [[ "$disk" == "$target_disk" ]] && continue
        find_matches_in_candidates "$target_file" "$target_metadata" "${source_lookup[$key]}" source_index matches_out "cross-disk"
    done
}

find_matches_in_candidates() {
    local target_file="$1"
    local target_metadata="$2"
    local candidates_str="$3"
    local -n src_index=$4
    local -n matches_array=$5
    local match_type="$6"

    IFS='|' read -r target_inode target_size target_disk <<< "$target_metadata"
    IFS='|' read -ra candidates <<< "$candidates_str"

    for candidate in "${candidates[@]}"; do
        [[ -z "$candidate" ]] && continue
        
        local cand_metadata="${src_index[$candidate]}"
        IFS='|' read -r cand_inode cand_size cand_disk <<< "$cand_metadata"

        # Skip if already hardlinked
        [[ "$cand_inode" == "$target_inode" ]] && continue

        # Byte-compare
        if cmp -s -- "$candidate" "$target_file"; then
            # Verify with hash if multiple candidates
            if (( ${#candidates[@]} > 1 )); then
                local target_hash candidate_hash
                target_hash=$(get_hash "$target_file" "$target_size")
                candidate_hash=$(get_hash "$candidate" "$cand_size")
                [[ "$target_hash" != "$candidate_hash" ]] && continue
            fi
            
            matches_array+=("$candidate|$cand_disk|$match_type")
        fi
    done
}

# HARDLINK CREATION FUNCTIONS
create_hardlink() {
    local dst_phys_path="$1"
    local src_path="$2"
    local src_disk="$3"
    local match_type="$4"

    ((matches++))

    local dst_disk rel_path target_phys_path
    dst_disk=$(get_disk_id "$dst_phys_path")
    rel_path="${dst_phys_path#/mnt/${dst_disk}/}"
    target_phys_path="/mnt/${src_disk}/${rel_path}"
    target_phys_path=$(echo "$target_phys_path" | sed 's|//|/|g')

    info "=========================================="
    info "MATCH #$matches ($match_type): $(basename "$dst_phys_path") -> $src_disk"
    info "  Source: $src_path"
    info "  Target: $target_phys_path"

    [[ "$DRY_RUN" == "yes" ]] && { info "  [DRY RUN]"; return; }
    [[ ! -f "$src_path" ]] && { warn "Source missing: $src_path"; return; }

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
}

# MAIN PROCESSING FUNCTIONS
process_all_files() {
    info "Processing destination files..."

    local scan_paths=()
    resolve_scan_paths "$DST_ROOT" scan_paths

    for disk_path in "${scan_paths[@]}"; do
        [[ ! -d "$disk_path" ]] && continue
        info "Scanning: $disk_path"

        while IFS= read -r -d '' dst_file; do
            ((scanned_dst++))
            (( scanned_dst % REPORT_EVERY == 0 )) && info "Scanned $scanned_dst destination files"

            [[ ! -f "$dst_file" ]] && continue

            local dst_metadata
            dst_metadata=$(get_file_metadata "$dst_file")

            # Find all matches
            local all_matches=()
            find_all_matches "$dst_file" "$dst_metadata" file_index size_disk_index all_matches

            # Process matches
            if (( ${#all_matches[@]} > 0 )); then
                process_matches "$dst_file" all_matches
            fi

        done < <(find "$disk_path" -type f -name '*.mkv' -print0 2>/dev/null)
    done
}

process_matches() {
    local dst_file="$1"
    shift
    local -a matches=("$@")

    # Report if multiple matches found
    if (( ${#matches[@]} > 1 )); then
        info "=========================================="
        info "MULTIPLE MATCHES for: $(basename "$dst_file")"
        info "  Found ${#matches[@]} matching sources:"
        for match in "${matches[@]}"; do
            IFS='|' read -r src_path src_disk match_type <<< "$match"
            info "    - $src_path ($match_type on $src_disk)"
        done
        info "=========================================="
    fi

    # Use first match to create hardlink
    local first_match="${matches[0]}"
    IFS='|' read -r src_path src_disk match_type <<< "$first_match"
    
    create_hardlink "$dst_file" "$src_path" "$src_disk" "$match_type"
}

# MAIN EXECUTION
main() {
    info "=========================================="
    info "  Unraid Hardlink Optimizer (Modular)"
    info "  Source: $SRC_ROOT"
    info "  Destination: $DST_ROOT"
    info "  Dry Run: $DRY_RUN"
    info "=========================================="

    load_hash_cache
    
    # Index source files
    if ! index_files "$SRC_ROOT" "*.mkv" scanned_src file_index size_disk_index; then
        warn "Failed to index sources"
        exit 1
    fi

    # Process destination files
    process_all_files

    info "=========================================="
    info "  Complete!"
    info "  Source files indexed: $scanned_src"
    info "  Destination files scanned: $scanned_dst"
    info "  Matches found: $matches"
    info "=========================================="
}

main "$@"
