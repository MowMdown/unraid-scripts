#!/usr/bin/env bash

# Unraid Hardlink Detection & Linking Script

set -uo pipefail

# Source directory containing the original files (torrents)
# This is where your seeding torrents live - the "master copies"
# Example: "/mnt/user/data/torrents" or "/mnt/disk1/torrents"
# The script will index all video files here and use them as hardlink sources
SRC_ROOT="/mnt/user/data/torrents"

# Destination directory to scan for duplicate files
# This is typically your media library managed by Plex/Jellyfin/Emby
# Example: "/mnt/user/data/media" or "/mnt/user/Movies"
# The script will find duplicates here and replace them with hardlinks to SRC_ROOT
DST_ROOT="/mnt/user/data/media"

# Space-separated list of Unraid cache/pool names to include in scans
# Leave as just "cache" for default, or add custom pools like "cache nvme ssd"
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
# Example: VERBOSE="yes" (recommended) or VERBOSE="no" (minimal output)
VERBOSE="yes"

# Enable debug logging - set to "yes" for troubleshooting, "no" for normal operation
# Shows detailed technical information useful for debugging issues
# Example: DEBUG="yes" (when troubleshooting) or DEBUG="no" (normal runs)
# Warning: Generates a lot of output
DEBUG="yes"

# Maximum number of disks to scan in parallel
# Set to 0 for auto-detection (uses half of CPU cores)
# Example: 4 scans 4 disks at once, 0 auto-tunes, 1 for sequential scanning
# Higher values speed up scanning but increase system load
MAX_PARALLEL_DISKS=4

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
log() { [[ "$VERBOSE" == "yes" ]] && echo "[LOG] $*" >&2; }
info() { echo "[INFO] $*"; }
debug() { [[ "$DEBUG" == "yes" ]] && echo "[DEBUG] $*" >&2; }
warn() { echo "[WARN] $*" >&2; }

get_disk_id() {
    local path="$1"
    # Only match /mnt/disk[0-9]+ (disk1, disk2, ... disk28, etc.)
    # Pools are handled separately via USR_POOL variable
    if [[ "$path" =~ ^/mnt/(disk[0-9]+)/ ]]; then
        echo "${BASH_REMATCH[1]}"
        return 0
    fi
    
    # Check if it's a pool from USR_POOL
    for pool in $USR_POOL; do
        if [[ "$path" =~ ^/mnt/${pool}/ ]]; then
            echo "$pool"
            return 0
        fi
    done
    
    # Not a recognized disk or pool - skip silently
    debug "Skipping unrecognized path: $path"
    return 1
}
# Hash cache functions
declare -A hash_cache

load_hash_cache() {
    [[ -f "$HASH_CACHE" ]] || return 0
    
    info "Loading hash cache from: $HASH_CACHE"
    local count=0 skipped=0
    
    while IFS='|' read -r inode size mtime hash; do
        # Validate line has all fields
        [[ -n "$inode" && -n "$size" && -n "$mtime" && -n "$hash" ]] || {
            ((skipped++))
            continue
        }
        
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
    [[ -r "$file" ]] || {
        debug "Cannot read file for hashing: $file"
        return 1
    }
    
    # Get inode and mtime for cache key
    local inode mtime
    read -r inode mtime < <(stat -c '%i %Y' -- "$file" 2>/dev/null) || {
        debug "Cannot stat file: $file"
        return 1
    }
    
    local cache_key="${inode}|${size}|${mtime}"
    
    # Check cache first
    if [[ -n "${hash_cache[$cache_key]:-}" ]]; then
        echo "${hash_cache[$cache_key]}"
        return 0
    fi
    
    # Compute hash with file lock to prevent modifications during hashing
    local hash
    {
        flock -s 201 || {
            warn "Cannot lock file for hashing: $file"
            return 1
        }
        
        # Verify file hasn't changed since stat
        local current_mtime
        current_mtime=$(stat -c '%Y' -- "$file" 2>/dev/null) || return 1
        
        if [[ "$current_mtime" != "$mtime" ]]; then
            debug "File modified during hash attempt: $file"
            return 1
        fi
        
        info "Computing hash: $file"
        hash=$(sha256sum -- "$file" 2>/dev/null | awk '{print $1}') || {
            warn "Hash computation failed: $file"
            return 1
        }
        
    } 201<"$file"
    
    # Store in cache (both memory and disk)
    hash_cache["$cache_key"]="$hash"
    
    {
        flock 202
        echo "${inode}|${size}|${mtime}|${hash}" >> "$HASH_CACHE"
    } 202>"$HASH_LOCK"
    
    echo "$hash"
    return 0
}
resolve_scan_paths() {
    local root="$1"
    local -n out_paths=$2
    out_paths=()
    
    if [[ "$root" =~ ^/mnt/user/ ]]; then
        # User share - expand to physical locations
        local rel_path="${root#/mnt/user/}"
        
        # Add all numbered disks (disk1 through disk28+)
        local disk_path
        for disk_path in /mnt/disk[0-9]*; do
            [[ -d "$disk_path/$rel_path" ]] || continue
            out_paths+=("$disk_path/$rel_path")
            log "Resolved: $disk_path/$rel_path"
        done
        
        # Add configured pools
        local pool
        for pool in $USR_POOL; do
            [[ -z "$pool" ]] && continue
            [[ -d "/mnt/$pool/$rel_path" ]] || continue
            out_paths+=("/mnt/$pool/$rel_path")
            log "Resolved: /mnt/$pool/$rel_path"
        done
        
        if (( ${#out_paths[@]} == 0 )); then
            warn "User share path not found on any disk or pool: $root"
            return 1
        fi
        
        debug "Expanded user share to ${#out_paths[@]} physical location(s)"
        
    else
        # Physical path - use directly
        if [[ -d "$root" ]]; then
            out_paths+=("$root")
        else
            warn "Physical path does not exist: $root"
            return 1
        fi
    fi
    
    return 0
}
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
            # Get file metadata with error handling
            if ! read -r size inode < <(stat -c '%s %i' -- "$phys_path" 2>/dev/null); then
                debug "Cannot stat file: $phys_path"
                continue
            fi
            
            # Get disk ID with validation
            if ! disk_id=$(get_disk_id "$phys_path"); then
                debug "Skipping file with unrecognized location: $phys_path"
                continue
            fi
            
            # Build index - avoid trailing pipe by checking if key exists
            key="${size}|${disk_id}"
            
            if [[ -n "${torrent_by_size_disk[$key]:-}" ]]; then
                # Key exists - append with pipe separator
                torrent_by_size_disk["$key"]+="${phys_path}|"
            else
                # New key - start without leading pipe
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
    
    # Optional: Warn if memory usage might be high
    if (( scanned_src > 50000 )); then
        warn "Large file count ($scanned_src files) - consider reducing scope or increasing RAM"
    fi
    
    return 0
}
scan_disk() {
    local disk_path="$1"
    info "Scanning disk: $disk_path"
    
    # Get the relative path to exclude source directories
    # If SRC_ROOT is /mnt/user/data/torrents, we want to skip:
    # /mnt/disk1/data/torrents, /mnt/disk2/data/torrents, /mnt/cache/data/torrents, etc.
    local src_rel="${SRC_ROOT#/mnt/user/}"
    
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
        # Skip source paths - check if this file is under the source tree
        # Example: if disk_path=/mnt/disk1 and src_rel=data/torrents
        # Skip /mnt/disk1/data/torrents/* but not /mnt/disk1/data/media/*
        if [[ "$dst_phys_path" == "$disk_path/$src_rel"/* ]]; then
            log "Skipping source file: $dst_phys_path"
            continue
        fi
        
        ((local_counter++))
        (( local_counter % 100 == 0 )) && log "Scanned $local_counter files on $(basename "$disk_path")"
        
        # Get metadata with error handling
        if ! read -r dst_size dst_inode < <(stat -c '%s %i' -- "$dst_phys_path" 2>/dev/null); then
            debug "Cannot stat: $dst_phys_path"
            continue
        fi
        
        # Get disk ID with validation
        if ! dst_disk=$(get_disk_id "$dst_phys_path"); then
            debug "Skipping file with unrecognized location: $dst_phys_path"
            continue
        fi
        
        # Try same-disk matches first (no data movement required)
        local same_disk_key="${dst_size}|${dst_disk}"
        if [[ -n "${torrent_by_size_disk[$same_disk_key]:-}" ]]; then
            try_match_candidates "$dst_phys_path" "$dst_size" "$dst_inode" "$dst_disk" \
                                "${torrent_by_size_disk[$same_disk_key]}" "same-disk"
        fi
        
        # Try cross-disk matches
        for key in "${!torrent_by_size_disk[@]}"; do
            IFS='|' read -r size disk <<< "$key"
            [[ "$size" != "$dst_size" ]] && continue
            [[ "$disk" == "$dst_disk" ]] && continue
            
            try_match_candidates "$dst_phys_path" "$dst_size" "$dst_inode" "$dst_disk" \
                                "${torrent_by_size_disk[$key]}" "cross-disk"
        done
        
    done < <(find "$disk_path" -type f \( "${find_expr[@]}" \) -print0 2>/dev/null)
    
    # Write local counter (no lock needed - one writer per file)
    echo "$local_counter" >> "/tmp/hardlinker/$COUNTER_DIR/scanned_dst_$(basename "$disk_path")"
    
    info "Completed scan of $disk_path ($local_counter files)"
}

process_destination_files() {
    info "Processing destination files from: $DST_ROOT"
    
    local scan_paths=()
    resolve_scan_paths "$DST_ROOT" scan_paths || {
        warn "Failed to resolve destination paths"
        return 1
    }
    
    info "Will scan ${#scan_paths[@]} destination location(s)"
    
    # Normalize to unique disk / pool roots
    local disk_roots=()
    declare -A seen_roots
    
    local p root
    for p in "${scan_paths[@]}"; do
        # Extract /mnt/diskX or /mnt/poolname
        root=$(echo "$p" | cut -d/ -f1-3)
        [[ -n "${seen_roots[$root]:-}" ]] && continue
        [[ -d "$root" ]] || continue
        seen_roots["$root"]=1
        disk_roots+=("$root")
    done
    
    (( ${#disk_roots[@]} == 0 )) && {
        warn "No valid destination disks or pools found to scan"
        return 1
    }
    
    info "Scanning ${#disk_roots[@]} unique disk/pool location(s)"
    
    # Auto-tune parallelism
    if (( MAX_PARALLEL_DISKS == 0 )); then
        # Disk I/O is bottleneck, not CPU
        # Use moderate parallelism to avoid thrashing
        local disk_count=0
        for d in /mnt/disk[0-9]*; do
            [[ -d "$d" ]] && ((disk_count++))
        done
        
        local cpu_cores
        cpu_cores=$(nproc)
        
        # Use 50% of cores or disk count, whichever is smaller
        MAX_PARALLEL_DISKS=$(( cpu_cores / 2 ))
        (( MAX_PARALLEL_DISKS > disk_count )) && MAX_PARALLEL_DISKS=$disk_count
        (( MAX_PARALLEL_DISKS < 1 )) && MAX_PARALLEL_DISKS=1
        
        info "Auto-tuned parallelism: $MAX_PARALLEL_DISKS concurrent disk scans"
    fi
    
    local active_jobs=0
    local failed_jobs=0
    
    for disk_path in "${disk_roots[@]}"; do
        [[ -d "$disk_path" ]] || { warn "Skipping missing path: $disk_path"; continue; }
        
        # Launch background job
        ( scan_disk "$disk_path" ) &
        ((active_jobs++))
        
        # Wait if at max parallelism
        while (( active_jobs >= MAX_PARALLEL_DISKS )); do
            if wait -n; then
                ((active_jobs--))
            else
                local exit_code=$?
                warn "Scan job failed with exit code: $exit_code"
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
    
    return 0
}


try_match_candidates() {
    local dst_phys_path="$1"
    local dst_size="$2"
    local dst_inode="$3"
    local dst_disk="$4"
    local candidates_str="$5"
    local match_type="$6"
    
    # Split candidates (remove empty elements from trailing pipes)
    IFS='|' read -ra candidates <<< "$candidates_str"
    
    local matched_any=0
    local src_path src_metadata src_inode src_size src_disk
    
    # Decide if we need to hash
    # Only hash if we have many candidates (>3) to avoid repeated cmp calls
    local use_hashing=0
    local dst_hash=""
    local candidate_count=0
    
    # Count non-empty candidates
    for src_path in "${candidates[@]}"; do
        [[ -n "$src_path" ]] && ((candidate_count++))
    done
    
    # If many candidates, hash the destination once and compare hashes
    if (( candidate_count > 3 )); then
        use_hashing=1
        dst_hash=$(get_hash "$dst_phys_path" "$dst_size") || use_hashing=0
        (( use_hashing )) && debug "Using hash comparison for $candidate_count candidates"
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
        if [[ "$src_inode" == "$dst_inode" && "$src_disk" == "$dst_disk" ]]; then
            log "Already hardlinked: $src_path <-> $dst_phys_path"
            continue
        fi
        
        # Verify both files still exist
        [[ -f "$src_path" && -f "$dst_phys_path" ]] || {
            debug "File disappeared during scan"
            continue
        }
        
        # Compare files
        local files_match=0
        
        if (( use_hashing )); then
            # Hash-based comparison
            local src_hash
            src_hash=$(get_hash "$src_path" "$src_size") || continue
            
            if [[ "$src_hash" == "$dst_hash" ]]; then
                # Hashes match - verify with cmp for certainty
                if cmp -s -- "$src_path" "$dst_phys_path" 2>/dev/null; then
                    files_match=1
                else
                    warn "Hash match but cmp failed: $src_path vs $dst_phys_path"
                fi
            fi
        else
            # Direct byte comparison (fast for mismatches, definitive for matches)
            if cmp -s -- "$src_path" "$dst_phys_path" 2>/dev/null; then
                files_match=1
            fi
        fi
        
        # Create hardlink if files match
        if (( files_match )); then
            create_hardlink "$dst_phys_path" "$src_path" "$src_disk" "$match_type"
            matched_any=1
            # Don't break - continue to create hardlinks for all matches
        fi
    done
    
    return $matched_any
}

create_hardlink() {
    local dst_phys_path="$1"
    local src_path="$2"
    local src_disk="$3"
    local match_type="$4"
    
    # Validate disk IDs early
    local dst_disk
    if ! dst_disk=$(get_disk_id "$dst_phys_path"); then
        debug "Cannot determine destination disk, skipping: $dst_phys_path"
        return 1
    fi
    
    # Verify we have valid disk IDs (not empty)
    if [[ -z "$src_disk" || -z "$dst_disk" ]]; then
        debug "Empty disk ID, skipping: $dst_phys_path"
        return 1
    fi
    
    # Construct target path on source disk
    local rel_path="${dst_phys_path#/mnt/${dst_disk}/}"
    local target_phys_path="/mnt/${src_disk}/${rel_path}"
    
    # Validate target path looks correct
    if [[ "$target_phys_path" != /mnt/* ]]; then
        warn "Invalid target path: $target_phys_path"
        return 1
    fi
    
    # Acquire global lock
    {
        flock 200 || {
            warn "Cannot acquire lock"
            return 1
        }
        
        # Update match counter
        echo 1 >> "/tmp/hardlinker/$COUNTER_DIR/matches"
        
        info "=========================================="
        info "MATCH ($match_type): $(basename "$dst_phys_path") -> $src_disk"
        info "  Source: $src_path"
        info "  Destination: $dst_phys_path"
        info "  New location: $target_phys_path"
        
        # Dry run check
        if [[ "$DRY_RUN" == "yes" ]]; then
            info "  [DRY RUN - no changes made]"
            info "=========================================="
            return 0
        fi
        
        # Verify source still exists
        if [[ ! -f "$src_path" ]]; then
            warn "Source file missing: $src_path"
            return 1
        fi
        
        # Create target directory structure if needed
        local target_dir
        target_dir=$(dirname -- "$target_phys_path")
        mkdir -p -- "$target_dir" 2>/dev/null || {
            warn "Cannot create directory: $target_dir"
            return 1
        }
        
        # Create hardlink
        if ! ln -- "$src_path" "$target_phys_path" 2>/dev/null; then
            warn "Cannot create hardlink: $target_phys_path"
            return 1
        fi
        
        # Mark original as duplicate (atomic rename)
        local backup_path="${dst_phys_path}.DUPLICATE"
        if ! mv -- "$dst_phys_path" "$backup_path" 2>/dev/null; then
            warn "Cannot rename original to .DUPLICATE: $dst_phys_path"
            # Clean up the hardlink we just created
            rm -f -- "$target_phys_path"
            return 1
        fi
        
        info "  ✓ Hardlink created"
        info "  ✓ Original marked: $backup_path"
        info "=========================================="
        
    } 200>"$HARDLINK_LOCK"
    
    return 0
}

main() {
    info "=========================================="
    info "  Unraid Hardlink Optimizer"
    info "  Source: $SRC_ROOT"
    info "  Destination: $DST_ROOT"
    info "  Dry Run: $DRY_RUN"
    info "  Max Parallel: $MAX_PARALLEL_DISKS"
    info "  File Extensions: $FILE_EXTENSIONS"
    info "=========================================="
    
    # Load hash cache
    load_hash_cache
    
    # Index source files
    if ! index_source_files; then
        warn "Failed to index source files"
        exit 1
    fi
    
    # Process destination files
    process_destination_files
    
    # Calculate statistics
    local scanned_dst=0 matches=0
    
    # Sum all destination scan counters
    for counter_file in "/tmp/hardlinker/$COUNTER_DIR"/scanned_dst_*; do
        [[ -f "$counter_file" ]] || continue
        while read -r count; do
            ((scanned_dst += count))
        done < "$counter_file"
    done
    
    # Count matches
    if [[ -f "/tmp/hardlinker/$COUNTER_DIR/matches" ]]; then
        matches=$(wc -l < "/tmp/hardlinker/$COUNTER_DIR/matches" 2>/dev/null || echo 0)
    fi
    
    # Clean up all temp files (all instances should be done by now)
    rm -rf /tmp/hardlinker/*
    
    info "=========================================="
    info "  Complete!"
    info "  Source files indexed: $scanned_src"
    info "  Destination files scanned: $scanned_dst"
    info "  Matches found: $matches"
    info "=========================================="
}

main "$@"
