package pathiv

import (
	"syscall"
	"sync"
	"crypto/sha256"

	// In newer Go versions, this has moved to just "sync/syncmap".
	"golang.org/x/sync/syncmap"

	"github.com/rfjakob/gocryptfs/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/internal/contentenc"
	"github.com/rfjakob/gocryptfs/internal/nametransform"
	"github.com/rfjakob/gocryptfs/internal/tlog"
)

var inodeTable syncmap.Map

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
		}
	}
	return fileIVs
}

// BlockIV returns the block IV for block number "blockNo".
func (fileIVs *FileIVs) BlockIV(blockNo uint64) []byte {
	fileIVs.lock.Lock()
	// If blockNo >= len(fileIVs.blocks) then assume the file size has increased
	// Append new BlockIV entries to the array. FIXME: Handle blockNo >= max int
	for blockNo >= uint64(len(fileIVs.Blocks)) {
		block := BlockIV{
			IV: cryptocore.RandBytes(contentenc.DefaultIVBits / 8),
		}
		fileIVs.Blocks = append(fileIVs.Blocks, block)
	}
	// Copy and return the requrested IV
	iv := make([]byte, contentenc.DefaultIVBits / 8)
	copy(iv, fileIVs.Blocks[blockNo].IV)
	fileIVs.lock.Unlock()
	return iv
}
