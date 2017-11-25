package pathiv

import (
	"io"
	"os"
	"syscall"
	"sync"
	"time"
	"encoding/gob"
	"crypto/sha256"
	"path/filepath"
	"sync/atomic"

	// In newer Go versions, this has moved to just "sync/syncmap".
	"golang.org/x/sync/syncmap"

	"github.com/rfjakob/gocryptfs/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/internal/contentenc"
	"github.com/rfjakob/gocryptfs/internal/nametransform"
	"github.com/rfjakob/gocryptfs/internal/tlog"
)

var inodeTable syncmap.Map
var ivChanged uint32

// Purpose identifies for which purpose the IV will be used. This is mixed into the
// derivation.
type Purpose string

const (
	// PurposeDirIV means the value will be used as a directory IV
	PurposeDirIV Purpose = "DIRIV"
	// PurposeSymlinkIV means the value will be used as the IV for symlink encryption
	PurposeSymlinkIV Purpose = "SYMLINKIV"
)

// Derive derives an IV from an encrypted path by hashing it with sha256
func Derive(path string, purpose Purpose) []byte {
	// Use null byte as separator as it cannot occur in the path
	extended := []byte(path + "\000" + string(purpose))
	hash := sha256.Sum256(extended)
	return hash[:nametransform.DirIVLen]
}

type DevIno struct {
	Dev uint64
	Ino uint64
}

type BlockIV struct {
	IV       []byte
	AuthData []byte
}

// FileIVs contains all IVs that are needed to create a file.
type FileIVs struct {
	lock     sync.Mutex
	ID       []byte
	Blocks   []BlockIV
}

// DeriveFile derives both IVs that are needed to create a file and returns them
// in a container struct.
func DeriveFile(path string, st syscall.Stat_t) (fileIVs *FileIVs) {
	numBlocks := (st.Size + contentenc.DefaultBS - 1) / contentenc.DefaultBS
	devino := DevIno{st.Dev, st.Ino}
	// See if we have that inode number already in the table
	v, found := inodeTable.Load(devino)
	if found {
		tlog.Debug.Printf("ino%d: newFile: found in the inode table", st.Ino)
		fileIVs = v.(*FileIVs)
		// Drop IVs if file was truncated
		fileIVs.lock.Lock()
		if numBlocks < int64(len(fileIVs.Blocks)) {
			fileIVs.Blocks = fileIVs.Blocks[:numBlocks]
			atomic.StoreUint32(&ivChanged, 1)
		}
		fileIVs.lock.Unlock()
	} else {
		// Create independent IVs for all blocks of the file
		blocks := make([]BlockIV, numBlocks)
		for i, _ := range blocks {
			blocks[i].IV = cryptocore.RandBytes(contentenc.DefaultIVBits / 8)
		}
		// Allocate fileIVs struct and set unique ID
		fileIVs = &FileIVs{
			ID:    cryptocore.RandBytes(contentenc.DefaultIVBits / 8),
			Blocks: blocks,
		}
		// Put fileIVs into the key-value storage
		v, found = inodeTable.LoadOrStore(devino, fileIVs)
		if found {
			// Another thread has stored a different value before we could.
			fileIVs = v.(*FileIVs)
		} else {
			tlog.Debug.Printf("ino%d: newFile: stored in the inode table", st.Ino)
			atomic.StoreUint32(&ivChanged, 1)
		}
	}
	return fileIVs
}

// BlockIV returns the block IV and authData for block number "blockNo".
func (fileIVs *FileIVs) LockBlockIV(blockNo uint64) *BlockIV {
	fileIVs.lock.Lock()
	// If blockNo >= len(fileIVs.blocks) then assume the file size has increased
	// Append new BlockIV entries to the array. FIXME: Handle blockNo >= max int
	for blockNo >= uint64(len(fileIVs.Blocks)) {
		block := BlockIV{
			IV: cryptocore.RandBytes(contentenc.DefaultIVBits / 8),
		}
		fileIVs.Blocks = append(fileIVs.Blocks, block)
		atomic.StoreUint32(&ivChanged, 1)
	}
	return &fileIVs.Blocks[blockNo]
}

func (fileIVs *FileIVs) UnlockBlockIV(changed bool) {
	if changed {
		atomic.StoreUint32(&ivChanged, 1)
	}
	fileIVs.lock.Unlock()
}

// Load file IVs from the disk
func LoadFileIVs(file string) {
	fd, err := os.Open(file)
	if err != nil {
		// Failure to load IVs is not critical, assume it doesn't exist yet
		return
	}
	enc := gob.NewDecoder(fd)
	for {
		var devino DevIno
		var fileIVs FileIVs
		// First decode device and inode number
		err = enc.Decode(&devino)
		if err == io.EOF {
			err = nil
			break
		}
		if err != nil {
			break
		}
		// Then read the associated file IVs struct
		err = enc.Decode(&fileIVs)
		if err != nil {
			break
		}
		// And add it to the inode table
		inodeTable.Store(devino, &fileIVs)
	}
	if err != nil {
		tlog.Warn.Printf("Failed to load file IVs: %s", err.Error())
	} else {
		tlog.Debug.Printf("Successfully loaded file IVs")
	}
	fd.Close()
}

// Save file IVs to the disk
func SaveFileIVs(file string) {
	if atomic.SwapUint32(&ivChanged, 0) == 0 {
		// If the IVs have not changed then don't do anything
		return
	}
	// We first store the IVs in a temporary file and later rename it
	tmp := file + ".tmp"
	fd, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
	if err != nil {
		tlog.Warn.Printf("Failed to store file IVs: %s", err.Error())
		atomic.StoreUint32(&ivChanged, 1)
		return
	}
	enc := gob.NewEncoder(fd)
	inodeTable.Range(func(k, v interface{}) bool {
		// First encode the key
		err = enc.Encode(k)
		if err != nil {
			return false
		}
		// Then lock and encode the value
		fileIVs := v.(*FileIVs)
		fileIVs.lock.Lock()
		err = enc.Encode(v)
		fileIVs.lock.Unlock()
		if err != nil {
			return false
		}
		// No error, continue with next key-value pair
		return true
	})
	// Abort immediately if something went wrong
	if err != nil {
		tlog.Warn.Printf("Failed to store file IVs: %s", err.Error())
		atomic.StoreUint32(&ivChanged, 1)
		fd.Close()
		os.Remove(tmp)
		return
	}
	// Otherwise close the file
	err = fd.Close()
	if err != nil {
		tlog.Warn.Printf("Failed to store file IVs: %s", err.Error())
		atomic.StoreUint32(&ivChanged, 1)
		os.Remove(tmp)
		return
	}
	// And rename it. If everything was successful set ivChanged to false
	err = os.Rename(tmp, file)
	if err != nil {
		tlog.Warn.Printf("Failed to store file IVs: %s", err.Error())
		atomic.StoreUint32(&ivChanged, 1)
		os.Remove(tmp)
	} else {
		tlog.Debug.Printf("Successfully saved file IVs")
	}
}

// Prune file IVs by checking content of cipherdir
func PruneFileIVs(cipherdir string) {
	inodes := make(map[DevIno]bool)

	err := filepath.Walk(cipherdir, func(path string, info os.FileInfo, err error) error {
		var st syscall.Stat_t
		if syscall.Stat(path, &st) == nil {
			devino := DevIno{st.Dev, st.Ino}
			inodes[devino] = true
		}
		return nil
	})
	if err != nil {
		tlog.Warn.Printf("Failed to walk files in cipherdir: %s", err.Error())
		return
	}

	inodeTable.Range(func(k, v interface{}) bool {
		_, found := inodes[k.(DevIno)]
		if !found {
			tlog.Debug.Printf("ino%d: not found in cipherdir, dropping file IVs", k.(DevIno).Ino)
			inodeTable.Delete(k)
			atomic.StoreUint32(&ivChanged, 1)
		}
		// Continue with next key-value pair
		return true
	})
}

var started bool
var quit chan bool
var done chan bool

// StartFileIVs first loads the file IVs from the disk and then starts a
// subroutine to periodically save the IVs if they changed
func StartFileIVs(file string, cipherdir string) {
	// Load previous state from the file
	LoadFileIVs(file)
	ivChanged = 0
	// Create channels for shutdown
	quit = make(chan bool, 1)
	done = make(chan bool, 1)
	started = true
	// Start subroutine to periodically save IVs
	go func() {
		save_ticker := time.NewTicker(60 * time.Second)
		prune_ticker := time.NewTicker(60 * time.Minute)
		for {
			select {
			case <- save_ticker.C:
				SaveFileIVs(file)
			case <- prune_ticker.C:
				PruneFileIVs(cipherdir)
			case <- quit:
				save_ticker.Stop()
				prune_ticker.Stop()
				SaveFileIVs(file)
				done <- true
				return
			}
		}
	}()
}

// Save file IVs one last time and shutdown subroutine
func StopFileIVs() {
	if started {
		quit <- true
		<- done
	}
}
