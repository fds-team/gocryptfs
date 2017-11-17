package pathiv

import (
	"syscall"

	"crypto/sha256"
	"encoding/binary"

	// In newer Go versions, this has moved to just "sync/syncmap".
	"golang.org/x/sync/syncmap"

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
	// PurposeFileID means the value will be used as the file ID in the file header
	PurposeFileID Purpose = "FILEID"
	// PurposeSymlinkIV means the value will be used as the IV for symlink encryption
	PurposeSymlinkIV Purpose = "SYMLINKIV"
	// PurposeBlock0IV means the value will be used as the IV of ciphertext block #0.
	PurposeBlock0IV Purpose = "BLOCK0IV"
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

// FileIVs contains both IVs that are needed to create a file.
type FileIVs struct {
	ID       []byte
	Block0IV []byte
}

// DeriveFile derives both IVs that are needed to create a file and returns them
// in a container struct.
func DeriveFile(path string, st syscall.Stat_t) (fileIVs FileIVs) {
	devino := DevIno{st.Dev, st.Ino}
	// See if we have that inode number already in the table
	// (even if Nlink has dropped to 1)
	v, found := inodeTable.Load(devino)
	if found {
		tlog.Debug.Printf("ino%d: newFile: found in the inode table", st.Ino)
		fileIVs = v.(FileIVs)
	} else {
		fileIVs.ID = Derive(path, PurposeFileID)
		fileIVs.Block0IV = Derive(path, PurposeBlock0IV)
		// Nlink > 1 means there is more than one path to this file.
		// Store the derived values so we always return the same data,
		// regardless of the path that is used to access the file.
		// This means that the first path wins.
		if st.Nlink > 1 {
			v, found = inodeTable.LoadOrStore(devino, fileIVs)
			if found {
				// Another thread has stored a different value before we could.
				fileIVs = v.(FileIVs)
			} else {
				tlog.Debug.Printf("ino%d: newFile: Nlink=%d, stored in the inode table", st.Ino, st.Nlink)
			}
		}
	}
	return fileIVs
}

// BlockIV returns the block IV for block number "blockNo".
func (fileIVs FileIVs) BlockIV(blockNo uint64) []byte {
	iv := make([]byte, len(fileIVs.Block0IV))
	copy(iv, fileIVs.Block0IV)
	// Add blockNo to one half of the iv
	lowBytes := iv[8:]
	lowInt := binary.BigEndian.Uint64(lowBytes)
	binary.BigEndian.PutUint64(lowBytes, lowInt+blockNo)
	return iv
}
