package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

// Config holds all configuration parameters
type Config struct {
	SrcRoot        string
	DstRoot        string
	UsrPool        []string
	HashCache      string
	DryRun         bool
	ReportEvery    int
	ParallelDisks  int
	Verbose        bool
	Debug          bool
	FileExtensions []string
	CounterDir     string
	HardlinkLock   string
	HashLock       string
}

// FileMetadata stores file information
type FileMetadata struct {
	Inode  uint64
	Size   int64
	DiskID string
}

// Hardlinker manages the hardlinking process
type Hardlinker struct {
	cfg               Config
	validMounts       map[string]bool
	torrentBySizeDisk map[string][]string
	fileMetadata      sync.Map
	hashCache         sync.Map
	scannedSrc        int
	mu                sync.RWMutex
	hashCacheMu       sync.Mutex
}

func main() {
	cfg := parseFlags()

	h := &Hardlinker{
		cfg:               cfg,
		validMounts:       make(map[string]bool),
		torrentBySizeDisk: make(map[string][]string),
	}

	if err := h.run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func parseFlags() Config {
	cfg := Config{}

	flag.StringVar(&cfg.SrcRoot, "src", "/mnt/user/data/torrents", "Source directory containing original files")
	flag.StringVar(&cfg.DstRoot, "dst", "/mnt/user/data/media", "Destination directory to scan for duplicates")
	poolsStr := flag.String("pools", "cache", "Space-separated list of Unraid pool names")
	flag.StringVar(&cfg.HashCache, "cache", "/mnt/user/appdata/hardlinks.txt", "Path to hash cache file")
	flag.BoolVar(&cfg.DryRun, "dry-run", true, "Dry run mode (no changes made)")
	flag.IntVar(&cfg.ReportEvery, "report-every", 250, "Report progress every N files")
	flag.IntVar(&cfg.ParallelDisks, "parallel-disks", 1, "Number of disks to scan concurrently")
	flag.BoolVar(&cfg.Verbose, "verbose", false, "Enable verbose logging")
	flag.BoolVar(&cfg.Debug, "debug", false, "Enable debug logging")
	extsStr := flag.String("extensions", "mkv", "Space-separated file extensions to scan")

	flag.Parse()

	cfg.UsrPool = strings.Fields(*poolsStr)
	cfg.FileExtensions = strings.Fields(*extsStr)
	cfg.CounterDir = fmt.Sprintf("/tmp/hardlinker/counters_%d", os.Getpid())
	cfg.HardlinkLock = "/tmp/hardlinker/hardlink.lock"
	cfg.HashLock = "/tmp/hardlinker/hash_cache.lock"

	return cfg
}

func (h *Hardlinker) log(format string, args ...interface{}) {
	if h.cfg.Verbose {
		fmt.Fprintf(os.Stderr, "[VERBOSE] "+format+"\n", args...)
	}
}

func (h *Hardlinker) info(format string, args ...interface{}) {
	fmt.Printf("[INFO] "+format+"\n", args...)
}

func (h *Hardlinker) warn(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "[WARN] "+format+"\n", args...)
}

func (h *Hardlinker) debug(format string, args ...interface{}) {
	if h.cfg.Debug {
		fmt.Fprintf(os.Stderr, "[DEBUG] "+format+"\n", args...)
	}
}

func (h *Hardlinker) run() error {
	h.info("==========================================")
	h.info("  Unraid Hardlink Optimizer")
	h.info("  Source: %s", h.cfg.SrcRoot)
	h.info("  Destination: %s", h.cfg.DstRoot)
	h.info("  Dry Run: %v", h.cfg.DryRun)
	h.info("  File Extensions: %v", h.cfg.FileExtensions)
	h.info("==========================================")

	// Create temp directories
	if err := os.MkdirAll(h.cfg.CounterDir, 0755); err != nil {
		return fmt.Errorf("failed to create counter directory: %w", err)
	}
	defer os.RemoveAll("/tmp/hardlinker")

	// Initialize valid mounts
	if err := h.initializeMounts(); err != nil {
		return err
	}

	// Load hash cache
	if err := h.loadHashCache(); err != nil {
		h.warn("Failed to load hash cache: %v", err)
	}

	// Index source files
	if err := h.indexSourceFiles(); err != nil {
		return fmt.Errorf("failed to index source files: %w", err)
	}

	// Process destination files
	scannedDst, matches, err := h.processDestinationFiles()
	if err != nil {
		return fmt.Errorf("failed to process destination files: %w", err)
	}

	// Print summary
	h.info("==========================================")
	h.info("  Complete!")
	h.info("  Source files indexed: %d", h.scannedSrc)
	h.info("  Destination files scanned: %d", scannedDst)
	h.info("  Matches found: %d", matches)
	h.info("==========================================")

	return nil
}

func (h *Hardlinker) initializeMounts() error {
	// Scan for numbered disks
	diskPattern := "/mnt/disk*"
	disks, err := filepath.Glob(diskPattern)
	if err != nil {
		return fmt.Errorf("failed to scan for disks: %w", err)
	}

	for _, disk := range disks {
		if info, err := os.Stat(disk); err == nil && info.IsDir() {
			diskName := filepath.Base(disk)
			h.validMounts[diskName] = true
			h.debug("Found disk: %s", diskName)
		}
	}

	// Add user-specified pools
	for _, pool := range h.cfg.UsrPool {
		poolPath := filepath.Join("/mnt", pool)
		if info, err := os.Stat(poolPath); err == nil && info.IsDir() {
			h.validMounts[pool] = true
			h.debug("Added pool: %s", pool)
		}
	}

	if len(h.validMounts) == 0 {
		return fmt.Errorf("no valid mounts found")
	}

	return nil
}

func (h *Hardlinker) loadHashCache() error {
	file, err := os.Open(h.cfg.HashCache)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer file.Close()

	h.info("Loading hash cache from: %s", h.cfg.HashCache)
	count := 0
	skipped := 0

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, "|")
		if len(parts) != 4 {
			skipped++
			continue
		}

		inode, size, mtime, hash := parts[0], parts[1], parts[2], parts[3]
		if inode == "" || size == "" || mtime == "" || hash == "" {
			skipped++
			continue
		}

		key := fmt.Sprintf("%s|%s|%s", inode, size, mtime)
		h.hashCache.Store(key, hash)
		count++
	}

	if skipped > 0 {
		h.info("Loaded %d cached hashes (%d invalid entries skipped)", count, skipped)
	} else {
		h.info("Loaded %d cached hashes", count)
	}

	return scanner.Err()
}

func (h *Hardlinker) getHash(filePath string, size int64) (string, error) {
	// Get file stat for cache key
	var stat syscall.Stat_t
	if err := syscall.Stat(filePath, &stat); err != nil {
		h.debug("Cannot stat file: %s", filePath)
		return "", err
	}

	inode := stat.Ino
	mtime := stat.Mtim.Sec
	cacheKey := fmt.Sprintf("%d|%d|%d", inode, size, mtime)

	// Check cache first (sync.Map)
	if val, ok := h.hashCache.Load(cacheKey); ok {
		return val.(string), nil
	}

	// Compute hash
	h.info("Computing hash: %s", filePath)
	file, err := os.Open(filePath)
	if err != nil {
		h.warn("Hash computation failed: %s", filePath)
		return "", err
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		h.warn("Hash computation failed: %s", filePath)
		return "", err
	}

	hash := hex.EncodeToString(hasher.Sum(nil))

	// Store in sync.Map
	h.hashCache.Store(cacheKey, hash)

	// Append to cache file safely
	h.hashCacheMu.Lock()
	if f, err := os.OpenFile(h.cfg.HashCache, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
		fmt.Fprintf(f, "%d|%d|%d|%s\n", inode, size, mtime, hash)
		f.Close()
	}
	h.hashCacheMu.Unlock()

	return hash, nil
}

func (h *Hardlinker) getDiskID(path string) (string, bool) {
	path = strings.TrimPrefix(path, "/mnt/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) == 0 {
		return "", false
	}

	diskID := parts[0]
	if _, ok := h.validMounts[diskID]; ok {
		return diskID, true
	}

	return "", false
}

func (h *Hardlinker) resolveScanPaths(root string) ([]string, error) {
	var paths []string

	if strings.HasPrefix(root, "/mnt/user/") {
		relPath := strings.TrimPrefix(root, "/mnt/user/")

		for mount := range h.validMounts {
			path := filepath.Join("/mnt", mount, relPath)
			if info, err := os.Stat(path); err == nil && info.IsDir() {
				paths = append(paths, path)
				h.debug("Resolved: %s", path)
			}
		}

		if len(paths) == 0 {
			h.warn("User share path not found on any disk or pool: %s", root)
			return nil, fmt.Errorf("no valid paths found")
		}

		h.debug("Expanded user share to %d physical location(s)", len(paths))
	} else {
		if info, err := os.Stat(root); err != nil || !info.IsDir() {
			h.warn("Physical path does not exist: %s", root)
			return nil, fmt.Errorf("path does not exist")
		}
		paths = append(paths, root)
		h.debug("Using physical path: %s", root)
	}

	return paths, nil
}

func (h *Hardlinker) indexSourceFiles() error {
	h.info("Indexing source files from: %s", h.cfg.SrcRoot)

	scanPaths, err := h.resolveScanPaths(h.cfg.SrcRoot)
	if err != nil {
		h.warn("Failed to resolve source paths")
		return err
	}

	h.debug("Scanning %d source location(s)", len(scanPaths))

	for _, dir := range scanPaths {
		if err := h.scanSourceDirectory(dir); err != nil {
			h.warn("Error scanning directory %s: %v", dir, err)
		}
	}

	if h.scannedSrc == 0 {
		h.warn("No source files found")
		return fmt.Errorf("no source files found")
	}

	h.info("Indexed %d source files across %d size/disk combinations", h.scannedSrc, len(h.torrentBySizeDisk))

	if h.scannedSrc > 50000 {
		h.warn("Large file count (%d files) - consider reducing scope or increasing RAM", h.scannedSrc)
	}

	return nil
}

func (h *Hardlinker) scanSourceDirectory(dir string) error {
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // Skip errors
		}

		if d.IsDir() {
			return nil
		}

		// Check file extension
		ext := strings.TrimPrefix(filepath.Ext(path), ".")
		matched := false
		for _, validExt := range h.cfg.FileExtensions {
			if strings.EqualFold(ext, validExt) {
				matched = true
				break
			}
		}
		if !matched {
			return nil
		}

		// Get file metadata
		var stat syscall.Stat_t
		if err := syscall.Stat(path, &stat); err != nil {
			h.debug("Cannot stat file: %s", path)
			return nil
		}

		size := stat.Size
		inode := stat.Ino

		// Get disk ID
		diskID, ok := h.getDiskID(path)
		if !ok {
			h.debug("Skipping file with unrecognized location: %s", path)
			return nil
		}

		sizeMB := (size + 524288) / 1048576
		h.log("Indexing: %s → size=%dMB, inode=%d, disk_id=%s", filepath.Base(path), sizeMB, inode, diskID)

		// Build index
		key := fmt.Sprintf("%d|%s", size, diskID)

		// Append to torrentBySizeDisk under lock
		h.mu.Lock()
		h.torrentBySizeDisk[key] = append(h.torrentBySizeDisk[key], path)
		h.scannedSrc++
		count := h.scannedSrc
		h.mu.Unlock()

		// Store file metadata in sync.Map (no lock needed)
		h.fileMetadata.Store(path, &FileMetadata{
			Inode:  inode,
			Size:   size,
			DiskID: diskID,
		})

		if count%h.cfg.ReportEvery == 0 {
			h.info("Indexed %d source files", count)
		}

		return nil
	})
}

func (h *Hardlinker) processDestinationFiles() (int, int, error) {
	h.info("Processing destination files from: %s", h.cfg.DstRoot)

	var scanPaths []string

	// Resolve destination paths
	if strings.HasPrefix(h.cfg.DstRoot, "/mnt/user/") {
		relDst := strings.TrimPrefix(h.cfg.DstRoot, "/mnt/user/")

		for mount := range h.validMounts {
			path := filepath.Join("/mnt", mount, relDst)
			info, err := os.Stat(path)
			if err != nil || !info.IsDir() {
				continue
			}
			scanPaths = append(scanPaths, path)
			h.debug("Adding destination path to scan: %s", path)
		}
	} else {
		info, err := os.Stat(h.cfg.DstRoot)
		if err != nil || !info.IsDir() {
			h.warn("Destination path does not exist: %s", h.cfg.DstRoot)
			return 0, 0, fmt.Errorf("destination path does not exist")
		}
		scanPaths = append(scanPaths, h.cfg.DstRoot)
		h.debug("Using physical destination path: %s", h.cfg.DstRoot)
	}

	numDisks := len(scanPaths)
	h.info("Will scan %d destination location(s)", numDisks)

	if numDisks == 0 {
		return 0, 0, fmt.Errorf("no destination paths found")
	}

	// Validate ParallelDisks
	if h.cfg.ParallelDisks < 1 {
		h.cfg.ParallelDisks = 1
	} else if h.cfg.ParallelDisks > numDisks {
		h.cfg.ParallelDisks = numDisks
	}

	h.info("Scanning up to %d disks simultaneously", h.cfg.ParallelDisks)

	// Semaphore and WaitGroup
	sem := make(chan struct{}, h.cfg.ParallelDisks)
	var wg sync.WaitGroup

	for i, diskPath := range scanPaths {
		wg.Add(1)
		go func(disk string, idx int) {
			defer wg.Done()
			sem <- struct{}{}           // acquire slot
			defer func() { <-sem }()    // release slot

			h.info("Scanning disk %d of %d: %s", idx+1, numDisks, disk)
			h.scanDisk(disk)
		}(diskPath, i)
	}

	wg.Wait() // wait for all scans to finish

	// Collect totals
	scannedDst := 0
	matches := 0

	// Read scanned counters
	files, _ := filepath.Glob(filepath.Join(h.cfg.CounterDir, "scanned_dst_*"))
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		if count, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil {
			scannedDst += count
		}
	}

	// Read matches
	matchFile := filepath.Join(h.cfg.CounterDir, "matches")
	if data, err := os.ReadFile(matchFile); err == nil {
		matches = strings.Count(string(data), "\n")
	}

	return scannedDst, matches, nil
}

func (h *Hardlinker) scanDisk(diskPath string) {
	h.info("Scanning disk: %s", diskPath)

	srcRel := strings.TrimPrefix(h.cfg.SrcRoot, "/mnt/user/")
	pruneDir := filepath.Join(diskPath, srcRel)
	h.debug("Will prune source directory: %s", pruneDir)

	localCounter := 0

	filepath.WalkDir(diskPath, func(dstPhysPath string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		// Prune source directory
		if d.IsDir() {
			if strings.HasPrefix(dstPhysPath, pruneDir) {
				return filepath.SkipDir
			}
			return nil
		}

		// Check file extension
		ext := strings.TrimPrefix(filepath.Ext(dstPhysPath), ".")
		matched := false
		for _, validExt := range h.cfg.FileExtensions {
			if strings.EqualFold(ext, validExt) {
				matched = true
				break
			}
		}
		if !matched {
			return nil
		}

		localCounter++
		if localCounter%100 == 0 {
			h.log("Scanned %d files on %s", localCounter, filepath.Base(diskPath))
		}

		// Get file metadata
		var stat syscall.Stat_t
		if err := syscall.Stat(dstPhysPath, &stat); err != nil {
			h.debug("Cannot stat: %s", dstPhysPath)
			return nil
		}

		dstSize := stat.Size
		dstInode := stat.Ino

		dstDisk, ok := h.getDiskID(dstPhysPath)
		if !ok {
			h.debug("Skipping file with unrecognized location: %s", dstPhysPath)
			return nil
		}

		sizeMB := (dstSize + 524288) / 1048576
		h.log("Scanning: %s → size=%dMB, inode=%d, disk_id=%s", filepath.Base(dstPhysPath), sizeMB, dstInode, dstDisk)

		// --- Same-disk matches ---
		sameDiskKey := fmt.Sprintf("%d|%s", dstSize, dstDisk)
		h.mu.RLock()
		if candidates, ok := h.torrentBySizeDisk[sameDiskKey]; ok {
			h.mu.RUnlock()
			h.tryMatchCandidates(dstPhysPath, dstSize, dstInode, dstDisk, candidates, "same-disk")
		} else {
			h.mu.RUnlock()
		}

		// --- Cross-disk matches (safe iteration) ---
		h.mu.RLock()
		keys := make([]string, 0, len(h.torrentBySizeDisk))
		for k := range h.torrentBySizeDisk {
			keys = append(keys, k)
		}
		h.mu.RUnlock()

		for _, key := range keys {
			parts := strings.Split(key, "|")
			if len(parts) != 2 {
				continue
			}

			keySize, _ := strconv.ParseInt(parts[0], 10, 64)
			keyDisk := parts[1]

			if keySize != dstSize || keyDisk == dstDisk {
				continue
			}

			h.mu.RLock()
			candidates := h.torrentBySizeDisk[key]
			h.mu.RUnlock()

			h.tryMatchCandidates(dstPhysPath, dstSize, dstInode, dstDisk, candidates, "cross-disk")
		}

		return nil
	})

	// Write counter
	counterFile := filepath.Join(h.cfg.CounterDir, fmt.Sprintf("scanned_dst_%s", filepath.Base(diskPath)))
	os.WriteFile(counterFile, []byte(fmt.Sprintf("%d\n", localCounter)), 0644)
	h.info("Completed scan of %s (%d files)", diskPath, localCounter)
}

func (h *Hardlinker) tryMatchCandidates(dstPhysPath string, dstSize int64, dstInode uint64, dstDisk string, candidates []string, matchType string) {
	candidateCount := len(candidates)
	useHashing := candidateCount > 2

	var dstHash string
	if useHashing {
		var err error
		dstHash, err = h.getHash(dstPhysPath, dstSize)
		if err != nil {
			useHashing = false
		} else {
			h.debug("Using hash comparison for %d candidates: %s", candidateCount, dstPhysPath)
		}
	}

	for _, srcPath := range candidates {
		if srcPath == "" {
			continue
		}

		// Load source metadata from sync.Map
		val, ok := h.fileMetadata.Load(srcPath)
		if !ok {
			h.debug("Missing metadata for candidate: %s", srcPath)
			continue
		}
		srcMeta := val.(*FileMetadata)

		// Skip if already hardlinked
		if srcMeta.Inode == dstInode && srcMeta.DiskID == dstDisk {
			continue
		}

		// Verify both files exist
		if _, err := os.Stat(srcPath); err != nil {
			continue
		}
		if _, err := os.Stat(dstPhysPath); err != nil {
			continue
		}

		filesMatch := false

		if useHashing {
			srcHash, err := h.getHash(srcPath, srcMeta.Size)
			if err != nil {
				continue
			}

			if srcHash == dstHash {
				if h.filesEqual(srcPath, dstPhysPath) {
					filesMatch = true
				} else {
					h.warn("Hash match but cmp failed: %s vs %s", srcPath, dstPhysPath)
				}
			}
		} else {
			filesMatch = h.filesEqual(srcPath, dstPhysPath)
		}

		if filesMatch {
			h.log("%s → size=%dMB, inode=%d, disk_id=%s", filepath.Base(dstPhysPath), dstSize/1024/1024, dstInode, dstDisk)
			h.createHardlink(dstPhysPath, srcPath, srcMeta.DiskID, matchType)
		}
	}
}

func (h *Hardlinker) filesEqual(file1, file2 string) bool {
	cmd := exec.Command("cmp", "-s", file1, file2)
	err := cmd.Run()
	return err == nil
}

func (h *Hardlinker) createHardlink(dstPhysPath, srcPath, srcDisk, matchType string) {
	dstDisk, ok := h.getDiskID(dstPhysPath)
	if !ok {
		h.debug("Cannot determine destination disk, skipping: %s", dstPhysPath)
		return
	}

	if srcDisk == "" || dstDisk == "" {
		h.debug("Empty disk ID, skipping: %s", dstPhysPath)
		return
	}

	relPath := strings.TrimPrefix(dstPhysPath, filepath.Join("/mnt", dstDisk)+"/")
	targetPhysPath := filepath.Join("/mnt", srcDisk, relPath)

	if !strings.HasPrefix(targetPhysPath, "/mnt/") {
		h.warn("Invalid target path: %s", targetPhysPath)
		return
	}

	// Record match
	matchFile := filepath.Join(h.cfg.CounterDir, "matches")
	f, _ := os.OpenFile(matchFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if f != nil {
		f.WriteString("1\n")
		f.Close()
	}

	// Get file size for display
	var stat syscall.Stat_t
	if err := syscall.Stat(dstPhysPath, &stat); err == nil {
		sizeMB := stat.Size / 1024 / 1024
		h.log("%s → size=%dMB, inode=%d, disk_id=%s", filepath.Base(dstPhysPath), sizeMB, stat.Ino, dstDisk)
	}

	h.info("MATCH (%s): %s -> %s", matchType, filepath.Base(dstPhysPath), srcDisk)
	h.info("  Source: %s", filepath.Dir(srcPath))
	h.info("  Destination: %s", filepath.Dir(dstPhysPath))
	h.info("  New location: %s", filepath.Dir(targetPhysPath))

	if h.cfg.DryRun {
		h.info("  [DRY RUN - no changes made]")
		h.info("==========================================")
		return
	}

	// Verify source exists
	if _, err := os.Stat(srcPath); err != nil {
		h.warn("Source file missing: %s", srcPath)
		return
	}

	// Create target directory
	if err := os.MkdirAll(filepath.Dir(targetPhysPath), 0755); err != nil {
		h.warn("Cannot create directory: %s", filepath.Dir(targetPhysPath))
		return
	}

	// Create hardlink
	if err := os.Link(srcPath, targetPhysPath); err != nil {
		h.warn("Cannot create hardlink: %s", targetPhysPath)
		return
	}

	// Rename original
	backupPath := dstPhysPath + ".DUPLICATE"
	if err := os.Rename(dstPhysPath, backupPath); err != nil {
		h.warn("Cannot rename original to .DUPLICATE: %s", dstPhysPath)
		os.Remove(targetPhysPath)
		return
	}

	h.info("  ✓ Hardlink created")
	h.info("  ✓ Original marked: %s", backupPath)
	h.info("==========================================")
}
