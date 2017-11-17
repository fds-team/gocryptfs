package fusefrontend_reverse

import (
	"bytes"
	"io"
	"os"
	"syscall"

	"github.com/hanwen/go-fuse/fuse"
	"github.com/hanwen/go-fuse/fuse/nodefs"

	"github.com/rfjakob/gocryptfs/internal/contentenc"
	"github.com/rfjakob/gocryptfs/internal/pathiv"
	"github.com/rfjakob/gocryptfs/internal/tlog"
)

type reverseFile struct {
	// Embed nodefs.defaultFile for a ENOSYS implementation of all methods
	nodefs.File
	// Backing FD
	fd *os.File
	// File header (contains the IV)
	header contentenc.FileHeader
	// Initialization vectors
	fileIVs *pathiv.FileIVs
	// Content encryption helper
	contentEnc *contentenc.ContentEnc
}

func (rfs *ReverseFS) newFile(relPath string, flags uint32) (nodefs.File, fuse.Status) {
	absPath, err := rfs.abs(rfs.decryptPath(relPath))
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	fd, err := os.OpenFile(absPath, int(flags), 0666)
	if err != nil {
		return nil, fuse.ToStatus(err)
	}
	var st syscall.Stat_t
	err = syscall.Fstat(int(fd.Fd()), &st)
	if err != nil {
		tlog.Warn.Printf("newFile: Fstat error: %v", err)
		return nil, fuse.ToStatus(err)
	}
	derivedIVs := pathiv.DeriveFile(relPath, st)
	header := contentenc.FileHeader{
		Version: contentenc.CurrentVersion,
		ID:      derivedIVs.ID,
	}
	return &reverseFile{
		File:       nodefs.NewDefaultFile(),
		fd:         fd,
		header:     header,
		fileIVs:    derivedIVs,
		contentEnc: rfs.contentEnc,
	}, fuse.OK
}

// GetAttr - FUSE call
// Triggered by fstat() from userspace
func (rf *reverseFile) GetAttr(*fuse.Attr) fuse.Status {
	tlog.Debug.Printf("reverseFile.GetAttr fd=%d\n", rf.fd.Fd())
	// The kernel should fall back to stat()
	return fuse.ENOSYS
}

// encryptBlocks - encrypt "plaintext" into a number of ciphertext blocks.
// "plaintext" must already be block-aligned.
func (rf *reverseFile) encryptBlocks(plaintext []byte, firstBlockNo uint64) []byte {
	inBuf := bytes.NewBuffer(plaintext)
	var outBuf bytes.Buffer
	bs := int(rf.contentEnc.PlainBS())
	for blockNo := firstBlockNo; inBuf.Len() > 0; blockNo++ {
		inBlock := inBuf.Next(bs)
		iv := rf.fileIVs.BlockIV(blockNo)
		outBlock := rf.contentEnc.EncryptBlockNonce(inBlock, blockNo, rf.fileIVs.ID, iv)
		outBuf.Write(outBlock)
	}
	return outBuf.Bytes()
}

// readBackingFile: read from the backing plaintext file, encrypt it, return the
// ciphertext.
// "off" ... ciphertext offset (must be >= HEADER_LEN)
// "length" ... ciphertext length
func (rf *reverseFile) readBackingFile(off uint64, length uint64) (out []byte, err error) {
	blocks := rf.contentEnc.ExplodeCipherRange(off, length)

	// Read the backing plaintext in one go
	alignedOffset, alignedLength := contentenc.JointPlaintextRange(blocks)
	plaintext := make([]byte, int(alignedLength))
	n, err := rf.fd.ReadAt(plaintext, int64(alignedOffset))
	if err != nil && err != io.EOF {
		tlog.Warn.Printf("readBackingFile: ReadAt: %s", err.Error())
		return nil, err
	}
	// Truncate buffer down to actually read bytes
	plaintext = plaintext[0:n]

	// Encrypt blocks
	ciphertext := rf.encryptBlocks(plaintext, blocks[0].BlockNo)

	// Crop down to the relevant part
	lenHave := len(ciphertext)
	skip := blocks[0].Skip
	endWant := int(skip + length)
	if lenHave > endWant {
		out = ciphertext[skip:endWant]
	} else if lenHave > int(skip) {
		out = ciphertext[skip:lenHave]
	} // else: out stays empty, file was smaller than the requested offset

	return out, nil
}

// Read - FUSE call
func (rf *reverseFile) Read(buf []byte, ioff int64) (resultData fuse.ReadResult, status fuse.Status) {
	length := uint64(len(buf))
	off := uint64(ioff)
	var out bytes.Buffer
	var header []byte

	// Synthesize file header
	if off < contentenc.HeaderLen {
		header = rf.header.Pack()
		// Truncate to requested part
		end := int(off) + len(buf)
		if end > len(header) {
			end = len(header)
		}
		header = header[off:end]
		// Write into output buffer and adjust offsets
		out.Write(header)
		hLen := uint64(len(header))
		off += hLen
		length -= hLen
	}

	// Read actual file data
	if length > 0 {
		fileData, err := rf.readBackingFile(off, length)
		if err != nil {
			return nil, fuse.ToStatus(err)
		}
		if len(fileData) == 0 {
			// If we could not read any actual data, we also don't want to
			// return the file header. An empty file stays empty in encrypted
			// form.
			return nil, fuse.OK
		}
		out.Write(fileData)
	}

	return fuse.ReadResultData(out.Bytes()), fuse.OK
}

// Release - FUSE call, close file
func (rf *reverseFile) Release() {
	rf.fd.Close()
}
