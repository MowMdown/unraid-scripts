#!/usr/bin/env bash

# Unraid Hardlink Detection & Linking Script

set -uo pipefail

# Source directory containing the original files (torrents)
# This is where your seeding torrents live - the "master copies"
# Example: "/mnt/user/data/torrents" or "/mnt/disk1/data/torrents"
# The script will index all video files here and use them as hardlink sources
SRC_ROOT="/mnt/user/data/torrents"

# Destination directory to scan for duplicate files
# This is typically your media library managed by Plex/Jellyfin/Emby
# Example: "/mnt/user/data/media" or "/mnt/disk1/data/media"
# "/mnt/user/data" alone should be avoided as it will scan the $SRC_ROOT files which is undesirable
# The script will find duplicates here and replace them with hardlinks to SRC_ROOT's correspoding disk
DST_ROOT="/mnt/user/data/media"

# Space-separated list of Unraid pool names to include in scans
# Example: "cache" or "cache nvme" or "cache fastpool ssdcache"
# Only needed if your shares use pools - the script auto-scans all disk1-diskN
USR_POOL="cache"

# Path to store hash cache file for faster re-runs
# Stores SHA256 hashes to avoid re-computing on subsequent runs
# Example: "/mnt/user/appdata/hardlinks.txt" or "/tmp/hashcache.txt"
# Make sure this path is on persistent storage, not /tmp
HASH_CACHE="/mnt/user/appdata/hardlinks.txt"

# Dry run mode - set to "yes" to simulate without making changes, "no" to execute
# Use "yes" for testing to see what would happen without modifying files
# Example: DRY_RUN="yes" (safe preview) or DRY_RUN="no" (actually create hardlinks)
# Always do a dry run first!
DRY_RUN="yes"

# Report progress every N files during indexing
# Lower number = more frequent updates but more output
# Example: 250 reports every 250 files, 1000 for less verbose output
# Useful for monitoring progress on large libraries
REPORT_EVERY=250

# Enable verbose logging - set to "yes" for detailed output, "no" for quiet
# Shows informational messages about script progress
# Example: VERBOSE="yes" (agressive output) or VERBOSE="no" (recommended)
VERBOSE="no"

# Enable debug logging - set to "yes" for troubleshooting, "no" for normal operation
# Shows detailed technical information useful for debugging issues
# Example: DEBUG="yes" (when troubleshooting) or DEBUG="no" (normal runs)
# Warning: Generates a lot of output
DEBUG="no"

# Maximum number of disks to scan in parallel
# Set to 0 for auto-detection (uses half of CPU cores)
# Example: 4 scans 4 disks at once, 0 auto-tunes, 1 for sequential scanning
# Higher values speed up scanning but increase system load
MAX_PARALLEL_DISKS=1

# Space-separated list of video file extensions to scan
# Add or remove extensions based on your media library
# Example: "mkv mp4 avi" or "mkv mp4 avi mov m4v wmv flv"
# Only files matching these extensions will be processed
FILE_EXTENSIONS="mkv mp4 avi"

# INTERNAL VARIABLES (DO NOT MODIFY)
SRC_REL_PATH="${SRC_ROOT#/mnt/user/}"
COUNTER_DIR="hardlink_counters.$$"
HARDLINK_LOCK="/tmp/hardlinker/hardlink.lock"
HASH_LOCK="/tmp/hardlinker/hash_cache.lock"

mkdir -p "/tmp/hardlinker/$COUNTER_DIR"

# Associative arrays
declare -A torrent_by_size_disk
declare -A hash_cache
declare -A file_metadata

# Counters
scanned_src=0

# LOGGING FUNCTIONS
log()   { [[ "$VERBOSE" == "yes" ]] && echo "[VERBOSE]-$*" >&2; }
info()  { echo "[INFO]----$*"; }
warn()  { echo "[WARN]----$*" >&2; }
debug() { [[ "$DEBUG" == "yes" ]] && echo "[DEBUG]---$*" >&2; }

get_disk_id() {
    local disks="${1#/mnt/}"
    disks="${disks%%/*}"
    [[ -n "${VALID_MOUNTS[$disks]:-}" ]] && echo "$disks" && return 0
    return 1
}

# HASH CACHE FUNCTIONS
load_hash_cache() {
    # Return if hash cache file does not exist
    [[ -f "$HASH_CACHE" ]] || return 0

    info "Loading hash cache from: $HASH_CACHE"
    local count=0 skipped=0

    # Read cached hashes line by line
    while IFS='|' read -r inode size mtime hash; do
        # Validate line has all fields
        [[ -n "$inode" && -n "$size" && -n "$mtime" && -n "$hash" ]] || { ((skipped++)); continue; }

        # Store by inode|size|mtime (inode is more reliable than path)
        hash_cache["${inode}|${size}|${mtime}"]="$hash"
        ((count++))
    done < "$HASH_CACHE"

    info "Loaded $count cached hashes${skipped:+ ($skipped invalid entries skipped)}"
}

get_hash() {
    local file="$1"
    local size="$2"

    # Validate file exists and is readable
    [[ -r "$file" ]] || { debug "Cannot read file for hashing: $file"; return 1; }

    # Get inode and mtime for cache key
    local inode mtime
    read -r inode mtime < <(stat -c '%i %Y' -- "$file" 2>/dev/null) || { debug "Cannot stat file: $file"; return 1; }

    local cache_key="${inode}|${size}|${mtime}"

    # Check cache first
    [[ -n "${hash_cache[$cache_key]:-}" ]] && { echo "${hash_cache[$cache_key]}"; return 0; }

    # Compute hash with file lock to prevent modifications during hashing
    local hash
    {
        flock -s 201 || { warn "Cannot lock file for hashing: $file"; return 1; }

        # Verify file hasn't changed since stat
        local current_mtime
        current_mtime=$(stat -c '%Y' -- "$file" 2>/dev/null) || return 1
        [[ "$current_mtime" != "$mtime" ]] && { debug "File modified during hash attempt: $file"; return 1; }

        info "Computing hash: $file"
        hash=$(sha256sum -- "$file" 2>/dev/null | awk '{print $1}') || { warn "Hash computation failed: $file"; return 1; }
    } 201<"$file"

    # Store in cache (both memory and disk)
    hash_cache["$cache_key"]="$hash"
    { flock 202; echo "${inode}|${size}|${mtime}|${hash}" >> "$HASH_CACHE"; } 202>"$HASH_LOCK"

    echo "$hash"
    return 0
}

# PATH RESOLUTION
resolve_scan_paths() {
    local root="$1"
    local -n out_paths=$2
    out_paths=()

    if [[ "$root" =~ ^/mnt/user/ ]]; then
        # Strip the /mnt/user/ prefix for user shares
        local rel_path="${root#/mnt/user/}"

        # Loop through all validated disks/pools
        local mount
        for mount in "${!VALID_MOUNTS[@]}"; do
            [[ -d "/mnt/$mount/$rel_path" ]] || continue
            out_paths+=("/mnt/$mount/$rel_path")
            debug "Resolved: /mnt/$mount/$rel_path"
        done

        # Warn if nothing found
        if (( ${#out_paths[@]} == 0 )); then
            warn "User share path not found on any disk or pool: $root"
            return 1
        fi

        debug "Expanded user share to ${#out_paths[@]} physical location(s)"
    else
        # Physical path fallback (outside /mnt/user/)
        [[ -d "$root" ]] || { warn "Physical path does not exist: $root"; return 1; }
        out_paths+=("$root")
        debug "Using physical path: $root"
    fi

    return 0
}

# SOURCE FILE INDEXING
index_source_files() {
    info "Indexing source files from: $SRC_ROOT"

    local scan_paths=()
    resolve_scan_paths "$SRC_ROOT" scan_paths || {
        warn "Failed to resolve source paths"
        return 1
    }

    debug "Scanning ${#scan_paths[@]} source location(s)"

    # Build find expression for file extensions
    local find_expr=()
    local first=1
    for ext in $FILE_EXTENSIONS; do
        if (( first )); then
            find_expr+=( "-name" "*.${ext}" )
            first=0
        else
            find_expr+=( "-o" "-name" "*.${ext}" )
        fi
    done

    local dir phys_path size inode disk_id key

    for dir in "${scan_paths[@]}"; do
        [[ -d "$dir" ]] || { warn "Skipping missing directory: $dir"; continue; }

        debug "Scanning: $dir"

        while IFS= read -r -d '' phys_path; do
            # Get file metadata
            if ! read -r size inode < <(stat -c '%s %i' -- "$phys_path" 2>/dev/null); then
                debug "Cannot stat file: $phys_path"
                continue
            fi

            # Get disk ID
            if ! disk_id=$(get_disk_id "$phys_path"); then
                debug "Skipping file with unrecognized location: $phys_path"
                continue
            fi

            # Strip the directory prefix for relative display
            local rel_file="${phys_path#${dir}/}"

            # Convert size to MB, rounded
            local size_mb=$(( (size + 524288) / 1048576 ))

            # Verbose output for every source file
            log "Indexing: $(basename "$phys_path") → size=${size_mb}MB, inode=$inode, disk_id=$disk_id"


            # Build index
            key="${size}|${disk_id}"
            if [[ -n "${torrent_by_size_disk[$key]:-}" ]]; then
                torrent_by_size_disk["$key"]+="${phys_path}|"
            else
                torrent_by_size_disk["$key"]="${phys_path}|"
            fi

            file_metadata["$phys_path"]="${inode}|${size}|${disk_id}"

            ((scanned_src++))
            (( scanned_src % REPORT_EVERY == 0 )) && info "Indexed $scanned_src source files"

        done < <(find "$dir" -type f \( "${find_expr[@]}" \) -print0 2>/dev/null)
    done

    if (( scanned_src == 0 )); then
        warn "No source files found"
        return 1
    fi

    info "Indexed $scanned_src source files across ${#torrent_by_size_disk[@]} size/disk combinations"

    # Optional: warn if memory usage might be high
    if (( scanned_src > 50000 )); then
        warn "Large file count ($scanned_src files) - consider reducing scope or increasing RAM"
    fi

    return 0
}

# DESTINATION FILE SCANNING
scan_disk() {
    local disk_path="$1"
    info "Scanning disk: $disk_path"

    # Extract relative source path (data/torrents)
    local src_rel="${SRC_ROOT#/mnt/user/}"

    local prune_dir="$disk_path/$src_rel"

    # Build find expression for file extensions
    local find_expr=()
    local first=1
    for ext in $FILE_EXTENSIONS; do
        if (( first )); then
            find_expr+=( "-name" "*.${ext}" )
            first=0
        else
            find_expr+=( "-o" "-name" "*.${ext}" )
        fi
    done

    local local_counter=0
    local dst_phys_path dst_size dst_inode dst_disk

    while IFS= read -r -d '' dst_phys_path; do
        ((local_counter++))
        (( local_counter % 100 == 0 )) && log "Scanned $local_counter files on $(basename "$disk_path")"

        if ! read -r dst_size dst_inode < <(stat -c '%s %i' -- "$dst_phys_path" 2>/dev/null); then
            debug "Cannot stat: $dst_phys_path"
            continue
        fi

        if ! dst_disk=$(get_disk_id "$dst_phys_path"); then
            debug "Skipping file with unrecognized location: $dst_phys_path"
            continue
        fi

        local size_mb=$(( (dst_size + 524288) / 1048576 ))
        log "Scanning: $(basename "$dst_phys_path") → size=${size_mb}MB, inode=$dst_inode, disk_id=$dst_disk"

        local same_disk_key="${dst_size}|${dst_disk}"
        if [[ -n "${torrent_by_size_disk[$same_disk_key]:-}" ]]; then
            try_match_candidates "$dst_phys_path" "$dst_size" "$dst_inode" "$dst_disk" \
                                "${torrent_by_size_disk[$same_disk_key]}" "same-disk"
        fi

        for key in "${!torrent_by_size_disk[@]}"; do
            IFS='|' read -r size disk <<< "$key"
            [[ "$size" != "$dst_size" ]] && continue
            [[ "$disk" == "$dst_disk" ]] && continue

            try_match_candidates "$dst_phys_path" "$dst_size" "$dst_inode" "$dst_disk" \
                                "${torrent_by_size_disk[$key]}" "cross-disk"
        done

    done < <(
        find "$disk_path" \
            \( -path "$prune_dir" -o -path "$prune_dir/*" \) -prune -o \
            -type f \( "${find_expr[@]}" \) -print0 2>/dev/null
    )

    echo "$local_counter" >> "/tmp/hardlinker/$COUNTER_DIR/scanned_dst_$(basename "$disk_path")"
    info "Completed scan of $disk_path ($local_counter files)"
}

process_destination_files() {
    info "Processing destination files from: $DST_ROOT"

    local scan_paths=()
    
    # Determine relative path under /mnt/user/ or /mnt/ for pools/disks
    local rel_dst
    if [[ "$DST_ROOT" =~ ^/mnt/user/ ]]; then
        rel_dst="${DST_ROOT#/mnt/user/}"
    else
        rel_dst="${DST_ROOT#/mnt/}"
    fi

    # Build scan paths per validated mount/pool, only the relative destination path
    for mount in "${!VALID_MOUNTS[@]}"; do
        local path="/mnt/$mount/$rel_dst"
        [[ -d "$path" ]] || continue

        # Skip the source directories
        if [[ "$SRC_ROOT" == "$path"* ]]; then
            debug "Skipping source directory on mount: $path"
            continue
        fi

        scan_paths+=("$path")
        debug "Adding destination path to scan: $path"
    done

    info "Will scan ${#scan_paths[@]} destination location(s)"

    # Auto-tune parallelism
    if (( MAX_PARALLEL_DISKS == 0 )); then
        local disk_count=${#scan_paths[@]}
        local cpu_cores
        cpu_cores=$(nproc)
        MAX_PARALLEL_DISKS=$(( cpu_cores / 2 ))
        (( MAX_PARALLEL_DISKS > disk_count )) && MAX_PARALLEL_DISKS=$disk_count
        (( MAX_PARALLEL_DISKS < 1 )) && MAX_PARALLEL_DISKS=1
        info "Auto-tuned parallelism: $MAX_PARALLEL_DISKS concurrent disk scans"
    fi

    local active_jobs=0 failed_jobs=0

    for disk_path in "${scan_paths[@]}"; do
        [[ -d "$disk_path" ]] || { warn "Skipping missing path: $disk_path"; continue; }

        # Launch background job
        ( scan_disk "$disk_path" ) &
        ((active_jobs++))

        while (( active_jobs >= MAX_PARALLEL_DISKS )); do
            if wait -n; then
                ((active_jobs--))
            else
                ((active_jobs--))
                ((failed_jobs++))
            fi
        done
    done

    # Wait for remaining jobs
    while (( active_jobs > 0 )); do
        if wait -n; then
            ((active_jobs--))
        else
            ((active_jobs--))
            ((failed_jobs++))
        fi
    done

    (( failed_jobs > 0 )) && warn "Completed with $failed_jobs failed scan job(s)"
}

# FILE MATCHING
try_match_candidates() {
    local dst_phys_path="$1"
    local dst_size="$2"
    local dst_inode="$3"
    local dst_disk="$4"
    local candidates_str="$5"
    local match_type="$6"

    # Split candidates string into array (ignore empty trailing elements)
    IFS='|' read -ra candidates <<< "$candidates_str"

    local matched_any=0
    local src_path src_metadata src_inode src_size src_disk files_match
    local use_hashing=0 dst_hash
    local candidate_count=0

    # Count valid candidates
    for src_path in "${candidates[@]}"; do
        [[ -n "$src_path" ]] && ((candidate_count++))
    done

    # Use hashing if many candidates
    if (( candidate_count > 2 )); then
        use_hashing=1
        dst_hash=$(get_hash "$dst_phys_path" "$dst_size") || use_hashing=0
        (( use_hashing )) && debug "Using hash comparison for $candidate_count candidates: $dst_phys_path"
    fi

    for src_path in "${candidates[@]}"; do
        [[ -z "$src_path" ]] && continue

        # Get source metadata
        src_metadata="${file_metadata[$src_path]:-}"
        if [[ -z "$src_metadata" ]]; then
            debug "Missing metadata for candidate: $src_path"
            continue
        fi

        IFS='|' read -r src_inode src_size src_disk <<< "$src_metadata"

        # Skip if already hardlinked (same inode on same disk)
        [[ "$src_inode" == "$dst_inode" && "$src_disk" == "$dst_disk" ]] && continue

        # Verify both files still exist
        [[ -f "$src_path" && -f "$dst_phys_path" ]] || continue

        files_match=0

        if (( use_hashing )); then
            # Hash-based comparison
            local src_hash
            src_hash=$(get_hash "$src_path" "$src_size") || continue
            if [[ "$src_hash" == "$dst_hash" ]]; then
                cmp -s -- "$src_path" "$dst_phys_path" 2>/dev/null && files_match=1 || warn "Hash match but cmp failed: $src_path vs $dst_phys_path"
            fi
        else
            # Direct byte comparison
            cmp -s -- "$src_path" "$dst_phys_path" 2>/dev/null && files_match=1
        fi

        if (( files_match )); then
            # Print verbose file info
            log "$(basename "$dst_phys_path") → size=$((dst_size / 1024 / 1024))MB, inode=$dst_inode, disk_id=$dst_disk"

            # Create hardlink
            create_hardlink "$dst_phys_path" "$src_path" "$src_disk" "$match_type"
            matched_any=1
        fi
    done

    return $matched_any
}

# HARDLINK CREATION
create_hardlink() {
    local dst_phys_path="$1"
    local src_path="$2"
    local src_disk="$3"
    local match_type="$4"

    local dst_disk
    if ! dst_disk=$(get_disk_id "$dst_phys_path"); then
        debug "Cannot determine destination disk, skipping: $dst_phys_path"
        return 1
    fi

    [[ -z "$src_disk" || -z "$dst_disk" ]] && { debug "Empty disk ID, skipping: $dst_phys_path"; return 1; }

    local rel_path="${dst_phys_path#/mnt/${dst_disk}/}"
    local target_phys_path="/mnt/${src_disk}/${rel_path}"

    [[ "$target_phys_path" != /mnt/* ]] && { warn "Invalid target path: $target_phys_path"; return 1; }

    {
        flock 200 || { warn "Cannot acquire lock"; return 1; }

        echo 1 >> "/tmp/hardlinker/$COUNTER_DIR/matches"

        # Verbose output: filename on top, directories below
        log "$(basename "$dst_phys_path") → size=$(( $(stat -c '%s' "$dst_phys_path") / 1024 / 1024 ))MB, inode=$(stat -c '%i' "$dst_phys_path"), disk_id=$dst_disk"
        info "MATCH ($match_type): $(basename "$dst_phys_path") -> $src_disk"
        info "  Source: $(dirname "$src_path")"
        info "  Destination: $(dirname "$dst_phys_path")"
        info "  New location: $(dirname "$target_phys_path")"

        if [[ "$DRY_RUN" == "yes" ]]; then
            info "  [DRY RUN - no changes made]"
            info "=========================================="
            return 0
        fi

        [[ -f "$src_path" ]] || { warn "Source file missing: $src_path"; return 1; }

        mkdir -p -- "$(dirname "$target_phys_path")" 2>/dev/null || { warn "Cannot create directory: $(dirname "$target_phys_path")"; return 1; }
        ln -- "$src_path" "$target_phys_path" 2>/dev/null || { warn "Cannot create hardlink: $target_phys_path"; return 1; }

        local backup_path="${dst_phys_path}.DUPLICATE"
        mv -- "$dst_phys_path" "$backup_path" 2>/dev/null || { warn "Cannot rename original to .DUPLICATE: $dst_phys_path"; rm -f -- "$target_phys_path"; return 1; }

        info "  ✓ Hardlink created"
        info "  ✓ Original marked: $backup_path"
        info "=========================================="

    } 200>"$HARDLINK_LOCK"
}

# MAIN EXECUTION
main() {
    info "=========================================="
    info "  Unraid Hardlink Optimizer"
    info "  Source: $SRC_ROOT"
    info "  Destination: $DST_ROOT"
    info "  Dry Run: $DRY_RUN"
    info "  Max Parallel: $MAX_PARALLEL_DISKS"
    info "  File Extensions: $FILE_EXTENSIONS"
    info "=========================================="

    # Initialize disks and user pools
    declare -A VALID_MOUNTS

    # Scan /mnt/ for numbered disks
    for disk_path in /mnt/disk[0-9]*; do
        [[ -d "$disk_path" ]] || continue
        disk_name="${disk_path##*/}"  # extract 'disk1', 'disk2', etc.
        VALID_MOUNTS["$disk_name"]=1
        debug "Found disk: $disk_name"
    done

    # Add user-specified pools (if any)
    if [[ -n "$USR_POOL" ]]; then
        for pool_name in $USR_POOL; do
            [[ -d "/mnt/$pool_name" ]] || continue
            VALID_MOUNTS["$pool_name"]=1
            debug "Added pool: $pool_name"
        done
    fi

    # Load hash cache
    load_hash_cache

    # Index source files
    if ! index_source_files; then
        warn "Failed to index source files"
        exit 1
    fi

    # Process destination files
    process_destination_files

    # Summarize results
    local scanned_dst=0 matches=0

    for counter_file in "/tmp/hardlinker/$COUNTER_DIR"/scanned_dst_*; do
        [[ -f "$counter_file" ]] || continue
        while read -r count; do
            ((scanned_dst += count))
        done < "$counter_file"
    done

    if [[ -f "/tmp/hardlinker/$COUNTER_DIR/matches" ]]; then
        matches=$(wc -l < "/tmp/hardlinker/$COUNTER_DIR/matches" 2>/dev/null || echo 0)
    fi

    # Clean up temp files
    rm -rf /tmp/hardlinker/*

    # Final summary
    info "=========================================="
    info "  Complete!"
    info "  Source files indexed: $scanned_src"
    info "  Destination files scanned: $scanned_dst"
    info "  Matches found: $matches"
    info "=========================================="
}

main "$@"
