package dav

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/aahl/tgnas/metadata"
	"github.com/aahl/tgnas/store"
	"golang.org/x/net/webdav"
)

const maxRecursiveObjects = 100000

var (
	ErrBadRequest = errors.New("bad request")
	ErrConflict   = errors.New("conflict")
	ErrNotFound   = errors.New("not found")
)

type ObjectStore interface {
	PutObject(ctx context.Context, input store.PutObjectInput) (store.PutObjectResult, error)
	GetObject(ctx context.Context, input store.GetObjectInput) (io.ReadCloser, store.ObjectInfo, error)
	// DeleteObject removes an object's metadata AND its underlying
	// Telegram message(s). WebDAV deletes must route through this
	// (rather than fs.meta.DeleteObject/DeletePrefix directly) so they
	// get the same real Telegram cleanup that S3 DeleteObject does --
	// previously WebDAV deletes only ever cleared metadata rows and left
	// every deleted file's Telegram message orphaned forever.
	DeleteObject(ctx context.Context, bucket, key string) error
}

type FileSystem struct {
	meta        metadata.Store
	objectStore ObjectStore
}

func NewFileSystem(meta metadata.Store, objectStore ObjectStore) *FileSystem {
	return &FileSystem{meta: meta, objectStore: objectStore}
}

func parsePath(p string) (bucket, key string, isRoot bool, err error) {
	decoded, err := url.PathUnescape(p)
	if err != nil {
		return "", "", false, ErrBadRequest
	}
	cleaned := path.Clean("/" + decoded)
	if cleaned == "/" {
		return "", "", true, nil
	}
	parts := strings.SplitN(strings.TrimPrefix(cleaned, "/"), "/", 2)
	bucket = parts[0]
	if bucket == "" {
		return "", "", true, nil
	}
	if len(parts) > 1 {
		key = parts[1]
		if strings.HasSuffix(decoded, "/") && key != "" && !strings.HasSuffix(key, "/") {
			key += "/"
		}
	}
	return bucket, key, false, nil
}

func canonicalCollectionKey(key string) string {
	if key == "" || strings.HasSuffix(key, "/") {
		return key
	}
	return key + "/"
}

func (fs *FileSystem) Mkdir(ctx context.Context, name string, perm os.FileMode) error {
	bucket, key, isRoot, err := parsePath(name)
	if err != nil {
		return err
	}
	if isRoot {
		return webdav.ErrForbidden
	}
	if err := fs.requireEnabledBucket(ctx, bucket); err != nil {
		return err
	}
	if key == "" {
		return webdav.ErrForbidden
	}
	key = canonicalCollectionKey(key)
	if exists, err := fs.checkCollectionExists(ctx, bucket, key); err != nil {
		return err
	} else if exists {
		return ErrConflict
	}
	sibling := strings.TrimSuffix(key, "/")
	if sibling != "" {
		if _, err := fs.meta.HeadObject(ctx, bucket, sibling); err == nil {
			return ErrConflict
		} else if !errors.Is(err, metadata.ErrNotFound) {
			return err
		}
	}
	parent := parentPrefix(key)
	if parent != "" {
		if _, err := fs.statCollection(ctx, bucket, parent); err != nil {
			if errors.Is(err, ErrNotFound) || errors.Is(err, metadata.ErrNotFound) {
				return ErrConflict
			}
			return err
		}
	}
	return fs.meta.PutObject(ctx, metadata.Object{
		Bucket:       bucket,
		Key:          key,
		Size:         0,
		ContentType:  "httpd/unix-directory",
		LastModified: time.Now().UTC(),
	}, nil)
}

func (fs *FileSystem) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (webdav.File, error) {
	bucket, key, isRoot, err := parsePath(name)
	if err != nil {
		return nil, err
	}
	writeMode := flag&(os.O_CREATE|os.O_WRONLY|os.O_RDWR|os.O_TRUNC|os.O_APPEND) != 0
	if writeMode && (isRoot || strings.HasSuffix(name, "/")) {
		return nil, webdav.ErrForbidden
	}
	if isRoot {
		return fs.openRootCollection(ctx)
	}
	if err := fs.requireEnabledBucket(ctx, bucket); err != nil {
		return nil, err
	}
	if key == "" || strings.HasSuffix(key, "/") {
		return fs.openCollection(ctx, bucket, canonicalCollectionKey(key))
	}
	if writeMode {
		if exists, err := fs.checkCollectionExists(ctx, bucket, canonicalCollectionKey(key)); err != nil {
			return nil, err
		} else if exists {
			return nil, ErrConflict
		}
		if fs.objectStore == nil {
			return nil, errors.New("object store is required")
		}
		return &davFile{fs: fs, ctx: ctx, bucket: bucket, key: key, write: &bytes.Buffer{}}, nil
	}
	obj, err := fs.meta.HeadObject(ctx, bucket, key)
	if err == nil {
		return &davFile{fs: fs, ctx: ctx, bucket: bucket, key: key, object: &obj}, nil
	}
	if !errors.Is(err, metadata.ErrNotFound) {
		return nil, err
	}
	if fs.collectionExists(ctx, bucket, canonicalCollectionKey(key)) {
		return fs.openCollection(ctx, bucket, canonicalCollectionKey(key))
	}
	return nil, ErrNotFound
}

func (fs *FileSystem) RemoveAll(ctx context.Context, name string) error {
	bucket, key, isRoot, err := parsePath(name)
	if err != nil {
		return err
	}
	if isRoot {
		return webdav.ErrForbidden
	}
	bucketRecord, err := fs.meta.GetBucket(ctx, bucket)
	if err != nil {
		if errors.Is(err, metadata.ErrNotFound) {
			return ErrNotFound
		}
		return err
	}
	if key == "" {
		if bucketRecord.Enabled {
			return webdav.ErrForbidden
		}
		return fs.meta.DeleteBucket(ctx, bucket)
	}
	if !bucketRecord.Enabled {
		return webdav.ErrForbidden
	}
	if strings.HasSuffix(key, "/") {
		return fs.removeAllUnderPrefix(ctx, bucket, canonicalCollectionKey(key))
	}
	if _, err := fs.meta.HeadObject(ctx, bucket, key); err == nil {
		// Route through the ObjectStore, not fs.meta directly, so the
		// object's Telegram message(s) actually get deleted too -- see
		// the ObjectStore interface doc comment above.
		return fs.objectStore.DeleteObject(ctx, bucket, key)
	} else if !errors.Is(err, metadata.ErrNotFound) {
		return err
	}
	if fs.collectionExists(ctx, bucket, canonicalCollectionKey(key)) {
		return fs.removeAllUnderPrefix(ctx, bucket, canonicalCollectionKey(key))
	}
	return ErrNotFound
}

// removeAllUnderPrefix recursively deletes every object under prefix by
// calling fs.objectStore.DeleteObject on each key individually, rather
// than a single bulk fs.meta.DeletePrefix call. Telegram message deletion
// is inherently per-object, so there's no way to batch this the way the
// metadata-only path could -- but it means each deleted file's Telegram
// message is actually cleaned up, matching what S3 DeleteObject already
// does, instead of leaving every file in a WebDAV-deleted folder orphaned
// in the source Telegram chat forever.
//
// Note this makes a recursive delete non-atomic: if DeleteObject hits a
// genuine, non-tolerated error partway through (deleteChunkMessage already
// tolerates "already gone" and Telegram's ~48h delete-age limit
// internally), objects deleted so far stay deleted and the error is
// returned immediately, leaving the rest of the folder in place.
func (fs *FileSystem) removeAllUnderPrefix(ctx context.Context, bucket, prefix string) error {
	count, err := fs.meta.CountObjects(ctx, bucket, prefix)
	if err != nil {
		return err
	}
	if count == 0 {
		return ErrNotFound
	}
	if count > maxRecursiveObjects {
		return fmt.Errorf("recursive delete exceeds %d object limit", maxRecursiveObjects)
	}
	objects, err := fs.meta.ListAllObjects(ctx, bucket, prefix)
	if err != nil {
		return err
	}
	for _, object := range objects {
		if err := fs.objectStore.DeleteObject(ctx, bucket, object.Key); err != nil {
			return err
		}
	}
	return nil
}

func (fs *FileSystem) Rename(ctx context.Context, oldName, newName string) error {
	return webdav.ErrForbidden
}

func (fs *FileSystem) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	bucket, key, isRoot, err := parsePath(name)
	if err != nil {
		return nil, err
	}
	if isRoot {
		return rootInfo(), nil
	}
	if err := fs.requireEnabledBucket(ctx, bucket); err != nil {
		return nil, err
	}
	if key == "" || strings.HasSuffix(key, "/") {
		info, err := fs.statCollection(ctx, bucket, canonicalCollectionKey(key))
		if err != nil && key != "" {
			return nil, davPathError("stat", name, err)
		}
		return info, err
	}
	obj, err := fs.meta.HeadObject(ctx, bucket, key)
	if err == nil {
		return &davFileInfo{name: path.Base(key), size: obj.Size, modTime: obj.LastModified, isDir: false, contentType: obj.ContentType, etag: obj.ETag}, nil
	}
	if !errors.Is(err, metadata.ErrNotFound) {
		return nil, davPathError("stat", name, err)
	}
	if fs.collectionExists(ctx, bucket, canonicalCollectionKey(key)) {
		info, err := fs.statCollection(ctx, bucket, canonicalCollectionKey(key))
		if err != nil {
			return nil, davPathError("stat", name, err)
		}
		return info, nil
	}
	return nil, davPathError("stat", name, ErrNotFound)
}

func (fs *FileSystem) openRootCollection(ctx context.Context) (webdav.File, error) {
	buckets, err := fs.meta.ListBuckets(ctx)
	if err != nil {
		return nil, err
	}
	children := make([]davFileInfo, 0, len(buckets))
	for _, bucket := range buckets {
		children = append(children, davFileInfo{name: bucket.Name, isDir: true, modTime: bucket.CreatedAt})
	}
	return &davFile{fs: fs, ctx: ctx, isDir: true, children: children}, nil
}

func (fs *FileSystem) openCollection(ctx context.Context, bucket, prefix string) (webdav.File, error) {
	if _, err := fs.statCollection(ctx, bucket, prefix); err != nil {
		return nil, err
	}
	children, err := fs.collectionChildren(ctx, bucket, prefix)
	if err != nil {
		return nil, err
	}
	return &davFile{fs: fs, ctx: ctx, bucket: bucket, key: prefix, isDir: true, children: children}, nil
}

func (fs *FileSystem) statCollection(ctx context.Context, bucket, prefix string) (os.FileInfo, error) {
	if prefix == "" {
		bucketRecord, err := fs.meta.GetBucket(ctx, bucket)
		if err != nil {
			if errors.Is(err, metadata.ErrNotFound) {
				return nil, ErrNotFound
			}
			return nil, err
		}
		if !bucketRecord.Enabled {
			return nil, webdav.ErrForbidden
		}
		return &davFileInfo{name: bucket, isDir: true, modTime: bucketRecord.CreatedAt}, nil
	}
	if obj, err := fs.meta.HeadObject(ctx, bucket, prefix); err == nil {
		return &davFileInfo{name: path.Base(strings.TrimSuffix(prefix, "/")), isDir: true, modTime: obj.LastModified, contentType: obj.ContentType, etag: obj.ETag}, nil
	} else if !errors.Is(err, metadata.ErrNotFound) {
		return nil, err
	}
	objects, err := fs.meta.ListObjects(ctx, metadata.ListQuery{Bucket: bucket, Prefix: prefix, Limit: 1})
	if err != nil {
		return nil, err
	}
	if len(objects) == 0 {
		return nil, ErrNotFound
	}
	return &davFileInfo{name: path.Base(strings.TrimSuffix(prefix, "/")), isDir: true, modTime: objects[0].LastModified}, nil
}

func (fs *FileSystem) collectionExists(ctx context.Context, bucket, prefix string) bool {
	exists, _ := fs.checkCollectionExists(ctx, bucket, prefix)
	return exists
}

func (fs *FileSystem) checkCollectionExists(ctx context.Context, bucket, prefix string) (bool, error) {
	if prefix == "" {
		return true, nil
	}
	_, err := fs.statCollection(ctx, bucket, prefix)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, ErrNotFound) || errors.Is(err, metadata.ErrNotFound) {
		return false, nil
	}
	return false, err
}

func (fs *FileSystem) collectionChildren(ctx context.Context, bucket, prefix string) ([]davFileInfo, error) {
	objects, err := fs.meta.ListAllObjects(ctx, bucket, prefix)
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	children := make([]davFileInfo, 0)
	for _, obj := range objects {
		remainder := strings.TrimPrefix(obj.Key, prefix)
		if remainder == "" {
			continue
		}
		if idx := strings.Index(remainder, "/"); idx >= 0 {
			name := remainder[:idx+1]
			if _, ok := seen[name]; ok {
				continue
			}
			seen[name] = struct{}{}
			children = append(children, davFileInfo{name: name, isDir: true, modTime: obj.LastModified})
			continue
		}
		children = append(children, davFileInfo{name: remainder, size: obj.Size, modTime: obj.LastModified, isDir: false, contentType: obj.ContentType, etag: obj.ETag})
	}
	sort.Slice(children, func(i, j int) bool { return children[i].name < children[j].name })
	return children, nil
}

func (fs *FileSystem) requireEnabledBucket(ctx context.Context, bucket string) error {
	bucketRecord, err := fs.meta.GetBucket(ctx, bucket)
	if err != nil {
		if errors.Is(err, metadata.ErrNotFound) {
			return ErrNotFound
		}
		return err
	}
	if !bucketRecord.Enabled {
		return webdav.ErrForbidden
	}
	return nil
}

func davPathError(op, name string, err error) error {
	if errors.Is(err, ErrNotFound) || errors.Is(err, metadata.ErrNotFound) {
		err = os.ErrNotExist
	}
	return &os.PathError{Op: op, Path: name, Err: err}
}

func parentPrefix(key string) string {
	trimmed := strings.TrimSuffix(key, "/")
	idx := strings.LastIndex(trimmed, "/")
	if idx < 0 {
		return ""
	}
	return trimmed[:idx+1]
}

type davFile struct {
	fs       *FileSystem
	ctx      context.Context
	bucket   string
	key      string
	object   *metadata.Object
	isDir    bool
	children []davFileInfo
	readPos  int
	reader   io.ReadCloser
	readBuf  *bytes.Reader
	write    *bytes.Buffer
	closed   bool
}

func (f *davFile) Read(p []byte) (int, error) {
	if f.isDir || f.object == nil {
		return 0, fmt.Errorf("is a directory")
	}
	if err := f.ensureReadBuffer(); err != nil {
		return 0, err
	}
	return f.readBuf.Read(p)
}

func (f *davFile) Write(p []byte) (int, error) {
	if f.write == nil {
		return 0, webdav.ErrForbidden
	}
	return f.write.Write(p)
}

func (f *davFile) Seek(offset int64, whence int) (int64, error) {
	if f.isDir || f.object == nil {
		return 0, fmt.Errorf("is a directory")
	}
	if err := f.ensureReadBuffer(); err != nil {
		return 0, err
	}
	return f.readBuf.Seek(offset, whence)
}

func (f *davFile) ensureReadBuffer() error {
	if f.readBuf != nil {
		return nil
	}
	rc, _, err := f.fs.objectStore.GetObject(f.ctx, store.GetObjectInput{Bucket: f.bucket, Key: f.key})
	if err != nil {
		return err
	}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		return err
	}
	f.readBuf = bytes.NewReader(data)
	return nil
}

func (f *davFile) Close() error {
	if f.closed {
		return nil
	}
	f.closed = true
	if f.reader != nil {
		return f.reader.Close()
	}
	if f.write != nil {
		_, err := f.fs.objectStore.PutObject(f.ctx, store.PutObjectInput{Bucket: f.bucket, Key: f.key, Size: int64(f.write.Len()), Body: bytes.NewReader(f.write.Bytes())})
		return err
	}
	return nil
}

func (f *davFile) Readdir(count int) ([]os.FileInfo, error) {
	if !f.isDir {
		return nil, fmt.Errorf("not a directory")
	}
	start := f.readPos
	if start >= len(f.children) {
		if count > 0 {
			return nil, io.EOF
		}
		return nil, nil
	}
	end := len(f.children)
	if count > 0 && start+count < end {
		end = start + count
	}
	f.readPos = end
	result := make([]os.FileInfo, end-start)
	for i := start; i < end; i++ {
		result[i-start] = &f.children[i]
	}
	return result, nil
}

func (f *davFile) Stat() (os.FileInfo, error) {
	if f.isDir {
		name := f.bucket
		if f.key != "" {
			name = path.Base(strings.TrimSuffix(f.key, "/"))
		}
		if name == "" {
			name = "/"
		}
		return &davFileInfo{name: name, isDir: true}, nil
	}
	if f.write != nil {
		return &davFileInfo{name: path.Base(f.key), size: int64(f.write.Len()), modTime: time.Now().UTC()}, nil
	}
	if f.object != nil {
		return &davFileInfo{name: path.Base(f.key), size: f.object.Size, modTime: f.object.LastModified, contentType: f.object.ContentType, etag: f.object.ETag}, nil
	}
	return nil, davPathError("stat", f.key, ErrNotFound)
}

type davFileInfo struct {
	name        string
	size        int64
	modTime     time.Time
	isDir       bool
	contentType string
	etag        string
}

func (fi *davFileInfo) Name() string { return fi.name }
func (fi *davFileInfo) Size() int64  { return fi.size }
func (fi *davFileInfo) Mode() os.FileMode {
	if fi.isDir {
		return os.ModeDir | 0755
	}
	return 0644
}
func (fi *davFileInfo) ModTime() time.Time { return fi.modTime }
func (fi *davFileInfo) IsDir() bool        { return fi.isDir }
func (fi *davFileInfo) Sys() any           { return nil }

func (fi *davFileInfo) ContentType(ctx context.Context) (string, error) {
	if fi.contentType != "" {
		return fi.contentType, nil
	}
	if fi.isDir {
		return "httpd/unix-directory", nil
	}
	return "application/octet-stream", nil
}

func (fi *davFileInfo) ETag(ctx context.Context) (string, error) {
	if fi.etag == "" {
		return "", nil
	}
	return fmt.Sprintf("%q", fi.etag), nil
}

func rootInfo() *davFileInfo {
	return &davFileInfo{name: "/", isDir: true}
}