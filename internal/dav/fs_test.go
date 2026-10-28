package dav

import (
	"context"
	"errors"
	"io"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aahl/tgnas/metadata"
	"github.com/aahl/tgnas/store"
	"golang.org/x/net/webdav"
)

type fakeObjectStore struct {
	objects map[string]string
	meta    metadata.Store
}

func (s fakeObjectStore) PutObject(ctx context.Context, input store.PutObjectInput) (store.PutObjectResult, error) {
	data, err := io.ReadAll(input.Body)
	if err != nil {
		return store.PutObjectResult{}, err
	}
	if s.objects == nil {
		return store.PutObjectResult{}, errors.New("objects map is nil")
	}
	s.objects[input.Bucket+"/"+input.Key] = string(data)
	return store.PutObjectResult{ETag: "etag"}, nil
}

func (s fakeObjectStore) GetObject(ctx context.Context, input store.GetObjectInput) (io.ReadCloser, store.ObjectInfo, error) {
	value, ok := s.objects[input.Bucket+"/"+input.Key]
	if !ok {
		return nil, store.ObjectInfo{}, store.ErrNoSuchKey
	}
	info := store.ObjectInfo{Bucket: input.Bucket, Key: input.Key, Size: int64(len(value)), LastModified: time.Now().UTC()}
	return io.NopCloser(strings.NewReader(value)), info, nil
}

func (s fakeObjectStore) DeleteObject(ctx context.Context, bucket, key string) error {
	delete(s.objects, bucket+"/"+key)
	if s.meta != nil {
		return s.meta.DeleteObject(ctx, bucket, key)
	}
	return nil
}

func openTestFS(t *testing.T) (*FileSystem, metadata.Store, fakeObjectStore) {
	t.Helper()
	meta, err := metadata.OpenSQLite(t.TempDir() + "/metadata.sqlite")
	if err != nil {
		t.Fatalf("OpenSQLite returned error: %v", err)
	}
	t.Cleanup(func() { _ = meta.Close() })
	objectStore := fakeObjectStore{objects: map[string]string{}, meta: meta}
	return NewFileSystem(meta, objectStore), meta, objectStore
}

func seedDAVBucket(t *testing.T, meta metadata.Store, name string, enabled bool) {
	t.Helper()
	if err := meta.UpsertBucket(context.Background(), metadata.Bucket{Name: name, ChatID: "123", CreatedAt: time.Now().UTC(), Enabled: enabled}); err != nil {
		t.Fatalf("UpsertBucket returned error: %v", err)
	}
}

func seedDAVObject(t *testing.T, meta metadata.Store, bucket, key string, size int64) {
	t.Helper()
	if err := meta.PutObject(context.Background(), metadata.Object{Bucket: bucket, Key: key, Size: size, ContentType: "text/plain", ETag: "etag", SHA256: "sha", LastModified: time.Now().UTC(), ChunkCount: 1, TelegramType: "document", UploadStrategy: "single"}, nil); err != nil {
		t.Fatalf("PutObject returned error: %v", err)
	}
}

func TestParsePathDecodesAndCleans(t *testing.T) {
	bucket, key, isRoot, err := parsePath("/photos/2026%2Fjan/../jan/file%20name.txt")
	if err != nil {
		t.Fatalf("parsePath returned error: %v", err)
	}
	if isRoot || bucket != "photos" || key != "2026/jan/file name.txt" {
		t.Fatalf("bucket=%q key=%q isRoot=%t", bucket, key, isRoot)
	}
}

func TestParsePathRejectsMalformedEscape(t *testing.T) {
	_, _, _, err := parsePath("/photos/%zz")
	if err == nil {
		t.Fatal("expected malformed escape error")
	}
}

func TestMkdirCreatesMarker(t *testing.T) {
	fs, meta, _ := openTestFS(t)
	ctx := context.Background()
	seedDAVBucket(t, meta, "photos", true)

	if err := fs.Mkdir(ctx, "/photos/2026/", 0755); err != nil {
		t.Fatalf("Mkdir returned error: %v", err)
	}

	obj, err := meta.HeadObject(ctx, "photos", "2026/")
	if err != nil {
		t.Fatalf("HeadObject returned error: %v", err)
	}
	if obj.Size != 0 || obj.ContentType != "httpd/unix-directory" {
		t.Fatalf("marker = %#v", obj)
	}
}

func TestMkdirBucketRootForbidden(t *testing.T) {
	fs, meta, _ := openTestFS(t)
	seedDAVBucket(t, meta, "photos", true)

	err := fs.Mkdir(context.Background(), "/photos", 0755)
	if !errors.Is(err, webdav.ErrForbidden) {
		t.Fatalf("err = %v, want ErrForbidden", err)
	}
}

func TestMkdirMissingParentConflict(t *testing.T) {
	fs, meta, _ := openTestFS(t)
	seedDAVBucket(t, meta, "photos", true)

	err := fs.Mkdir(context.Background(), "/photos/2026/jan/", 0755)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict", err)
	}
}

func TestStatRootBucketImplicitDirectoryAndFile(t *testing.T) {
	fs, meta, _ := openTestFS(t)
	ctx := context.Background()
	seedDAVBucket(t, meta, "photos", true)
	seedDAVObject(t, meta, "photos", "2026/jan/a.txt", 12)

	for _, name := range []string{"/", "/photos", "/photos/2026/"} {
		info, err := fs.Stat(ctx, name)
		if err != nil {
			t.Fatalf("Stat(%q) returned error: %v", name, err)
		}
		if !info.IsDir() {
			t.Fatalf("Stat(%q).IsDir() = false", name)
		}
	}

	info, err := fs.Stat(ctx, "/photos/2026/jan/a.txt")
	if err != nil {
		t.Fatalf("Stat file returned error: %v", err)
	}
	if info.IsDir() || info.Size() != 12 || info.Name() != "a.txt" {
		t.Fatalf("file info = %#v", info)
	}
}

func TestStatPrefersObjectWhenObjectAndCollectionSharePath(t *testing.T) {
	fs, meta, _ := openTestFS(t)
	ctx := context.Background()
	seedDAVBucket(t, meta, "photos", true)
	seedDAVObject(t, meta, "photos", "foo", 7)
	seedDAVObject(t, meta, "photos", "foo/bar.txt", 1)

	info, err := fs.Stat(ctx, "/photos/foo")
	if err != nil {
		t.Fatalf("Stat file returned error: %v", err)
	}
	if info.IsDir() || info.Size() != 7 || info.Name() != "foo" {
		t.Fatalf("file info = %#v", info)
	}

	info, err = fs.Stat(ctx, "/photos/foo/")
	if err != nil {
		t.Fatalf("Stat collection returned error: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("collection IsDir() = false")
	}
}

func TestOpenFilePrefersObjectWhenObjectAndCollectionSharePath(t *testing.T) {
	fs, meta, objectStore := openTestFS(t)
	ctx := context.Background()
	seedDAVBucket(t, meta, "photos", true)
	seedDAVObject(t, meta, "photos", "foo", 4)
	seedDAVObject(t, meta, "photos", "foo/bar.txt", 1)
	objectStore.objects["photos/foo"] = "body"

	file, err := fs.OpenFile(ctx, "/photos/foo", os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("OpenFile returned error: %v", err)
	}
	data, err := io.ReadAll(file)
	if err != nil {
		t.Fatalf("ReadAll returned error: %v", err)
	}
	if string(data) != "body" {
		t.Fatalf("body = %q, want body", data)
	}

	collection, err := fs.OpenFile(ctx, "/photos/foo/", os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("OpenFile collection returned error: %v", err)
	}
	if _, err := collection.Readdir(0); err != nil {
		t.Fatalf("Readdir collection returned error: %v", err)
	}
}

func TestRemoveAllPrefersObjectWhenObjectAndCollectionSharePath(t *testing.T) {
	fs, meta, _ := openTestFS(t)
	ctx := context.Background()
	seedDAVBucket(t, meta, "photos", true)
	seedDAVObject(t, meta, "photos", "foo", 7)
	seedDAVObject(t, meta, "photos", "foo/bar.txt", 1)

	if err := fs.RemoveAll(ctx, "/photos/foo"); err != nil {
		t.Fatalf("RemoveAll returned error: %v", err)
	}
	if _, err := meta.HeadObject(ctx, "photos", "foo"); !errors.Is(err, metadata.ErrNotFound) {
		t.Fatalf("file err = %v, want ErrNotFound", err)
	}
	if _, err := meta.HeadObject(ctx, "photos", "foo/bar.txt"); err != nil {
		t.Fatalf("collection child missing: %v", err)
	}
}

func TestOpenFilePutRejectsWhenCollectionExists(t *testing.T) {
	fs, meta, _ := openTestFS(t)
	ctx := context.Background()
	seedDAVBucket(t, meta, "photos", true)
	seedDAVObject(t, meta, "photos", "dir/child.txt", 1)

	_, err := fs.OpenFile(ctx, "/photos/dir", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict", err)
	}
}

func TestMkdirRejectsWhenCollectionAlreadyExists(t *testing.T) {
	fs, meta, _ := openTestFS(t)
	ctx := context.Background()
	seedDAVBucket(t, meta, "photos", true)
	seedDAVObject(t, meta, "photos", "dir/child.txt", 1)

	err := fs.Mkdir(ctx, "/photos/dir/", 0755)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict", err)
	}
}

func TestMkdirRejectsWhenObjectExistsAtSiblingKey(t *testing.T) {
	fs, meta, _ := openTestFS(t)
	ctx := context.Background()
	seedDAVBucket(t, meta, "photos", true)
	seedDAVObject(t, meta, "photos", "dir", 5)

	err := fs.Mkdir(ctx, "/photos/dir/", 0755)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict", err)
	}
}

func TestStatUnknownBucketAndDisabledBucket(t *testing.T) {
	fs, meta, _ := openTestFS(t)
	seedDAVBucket(t, meta, "archive", false)

	_, err := fs.Stat(context.Background(), "/unknown/")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown err = %v, want ErrNotFound", err)
	}
	_, err = fs.Stat(context.Background(), "/archive/")
	if !errors.Is(err, webdav.ErrForbidden) {
		t.Fatalf("disabled err = %v, want ErrForbidden", err)
	}
}

func TestOpenCollectionListsDirectChildren(t *testing.T) {
	fs, meta, _ := openTestFS(t)
	ctx := context.Background()
	seedDAVBucket(t, meta, "photos", true)
	seedDAVObject(t, meta, "photos", "2026/", 0)
	seedDAVObject(t, meta, "photos", "2026/jan/a.txt", 1)
	seedDAVObject(t, meta, "photos", "2026/jan/b.txt", 1)
	seedDAVObject(t, meta, "photos", "2026/feb/c.txt", 1)
	seedDAVObject(t, meta, "photos", "2026/root.txt", 1)

	file, err := fs.OpenFile(ctx, "/photos/2026/", os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("OpenFile returned error: %v", err)
	}
	infos, err := file.Readdir(0)
	if err != nil {
		t.Fatalf("Readdir returned error: %v", err)
	}
	var names []string
	for _, info := range infos {
		names = append(names, info.Name())
	}
	sort.Strings(names)
	want := []string{"feb/", "jan/", "root.txt"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("names = %v, want %v", names, want)
	}
}

func TestOpenFilePutWritesObject(t *testing.T) {
	fs, meta, objectStore := openTestFS(t)
	ctx := context.Background()
	seedDAVBucket(t, meta, "photos", true)

	file, err := fs.OpenFile(ctx, "/photos/hello.txt", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		t.Fatalf("OpenFile returned error: %v", err)
	}
	if _, err := file.Write([]byte("hello")); err != nil {
		t.Fatalf("Write returned error: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
	if got := objectStore.objects["photos/hello.txt"]; got != "hello" {
		t.Fatalf("stored body = %q, want hello", got)
	}
}

func TestOpenFilePutToPathEndingInSlashRejected(t *testing.T) {
	fs, meta, _ := openTestFS(t)
	seedDAVBucket(t, meta, "photos", true)

	_, err := fs.OpenFile(context.Background(), "/photos/dir/", os.O_CREATE|os.O_WRONLY, 0644)
	if !errors.Is(err, webdav.ErrForbidden) {
		t.Fatalf("err = %v, want ErrForbidden", err)
	}
}

func TestRemoveAllDeletesFileDirectoryAndOrphanBucket(t *testing.T) {
	fs, meta, _ := openTestFS(t)
	ctx := context.Background()
	seedDAVBucket(t, meta, "photos", true)
	seedDAVBucket(t, meta, "archive", false)
	seedDAVObject(t, meta, "photos", "a.txt", 1)
	seedDAVObject(t, meta, "photos", "dir/a.txt", 1)
	seedDAVObject(t, meta, "photos", "dir/b.txt", 1)
	seedDAVObject(t, meta, "archive", "old.txt", 1)

	if err := fs.RemoveAll(ctx, "/photos/a.txt"); err != nil {
		t.Fatalf("RemoveAll file returned error: %v", err)
	}
	if _, err := meta.HeadObject(ctx, "photos", "a.txt"); !errors.Is(err, metadata.ErrNotFound) {
		t.Fatalf("file err = %v, want ErrNotFound", err)
	}
	if err := fs.RemoveAll(ctx, "/photos/dir/"); err != nil {
		t.Fatalf("RemoveAll dir returned error: %v", err)
	}
	if count, err := meta.CountObjects(ctx, "photos", "dir/"); err != nil || count != 0 {
		t.Fatalf("dir count=%d err=%v, want 0 nil", count, err)
	}
	if err := fs.RemoveAll(ctx, "/archive/"); err != nil {
		t.Fatalf("RemoveAll orphan bucket returned error: %v", err)
	}
	if _, err := meta.GetBucket(ctx, "archive"); !errors.Is(err, metadata.ErrNotFound) {
		t.Fatalf("orphan bucket err = %v, want ErrNotFound", err)
	}
}

func TestRemoveAllConfiguredBucketForbidden(t *testing.T) {
	fs, meta, _ := openTestFS(t)
	seedDAVBucket(t, meta, "photos", true)

	err := fs.RemoveAll(context.Background(), "/photos/")
	if !errors.Is(err, webdav.ErrForbidden) {
		t.Fatalf("err = %v, want ErrForbidden", err)
	}
}
