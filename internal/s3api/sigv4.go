package s3api

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const EmptyPayloadSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// Streaming (aws-chunked) payload hash tokens. Requests signed with one of
// these values transfer their body as a series of individually signed
// chunks rather than a single hashed payload (used by minio-go-based
// clients such as Kopia). See attachChunkedBody and chunkedPayloadReader
// below for how these are verified and decoded.
const (
	StreamingPayloadSHA256        = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
	StreamingPayloadSHA256Trailer = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"
)

func isStreamingPayloadHash(hash string) bool {
	return hash == StreamingPayloadSHA256 || hash == StreamingPayloadSHA256Trailer
}

type Identity struct {
	AccessKey string
	Presigned bool
}

type SigV4Verifier struct {
	region  string
	keys    map[string]string
	clock   func() time.Time
	maxSkew time.Duration
	logger  *log.Logger
}

type SigV4VerifierOption func(*SigV4Verifier)

func WithSigV4Clock(clock func() time.Time) SigV4VerifierOption {
	return func(v *SigV4Verifier) {
		v.clock = clock
	}
}

func WithSigV4MaxSkew(maxSkew time.Duration) SigV4VerifierOption {
	return func(v *SigV4Verifier) {
		v.maxSkew = maxSkew
	}
}

func WithSigV4Logger(logger *log.Logger) SigV4VerifierOption {
	return func(v *SigV4Verifier) {
		v.logger = logger
	}
}

type sigV4Authorization struct {
	accessKey     string
	date          string
	region        string
	service       string
	signedHeaders []string
	signature     string
	xAmzDate      string
	expires       time.Duration
	presigned     bool
}

func NewSigV4Verifier(region string, keys map[string]string, opts ...SigV4VerifierOption) *SigV4Verifier {
	clonedKeys := make(map[string]string, len(keys))
	for accessKey, secret := range keys {
		clonedKeys[accessKey] = secret
	}
	verifier := &SigV4Verifier{region: region, keys: clonedKeys, clock: time.Now, maxSkew: 15 * time.Minute}
	for _, opt := range opts {
		opt(verifier)
	}
	return verifier
}

func (v *SigV4Verifier) Verify(r *http.Request) (Identity, error) {
	logger := v.logger
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	auth, err := parseSigV4RequestAuth(r)
	if err != nil {
		logger.Printf("debug event=sigv4_verify_failure stage=%q method=%q path=%q raw_query=%q host=%q scheme=%q error=%q", "parse", r.Method, r.URL.Path, r.URL.RawQuery, r.Host, r.URL.Scheme, sanitizeLogError(err))
		return Identity{}, ErrSignatureDoesNotMatch
	}
	if auth.region != v.region || auth.service != "s3" {
		logger.Printf("debug event=sigv4_verify_failure stage=%q method=%q path=%q raw_query=%q host=%q scheme=%q access_key=%q request_region=%q request_service=%q scope=%q signed_headers=%q error=%q", "scope", r.Method, r.URL.Path, r.URL.RawQuery, r.Host, r.URL.Scheme, auth.accessKey, auth.region, auth.service, auth.date+"/"+v.region+"/s3/aws4_request", strings.Join(auth.signedHeaders, ";"), "region or service mismatch")
		return Identity{}, ErrSignatureDoesNotMatch
	}
	if auth.accessKey == "" {
		return Identity{}, ErrInvalidAccessKeyID
	}

	secret, ok := v.keys[auth.accessKey]
	if !ok {
		return Identity{}, ErrInvalidAccessKeyID
	}

	if auth.xAmzDate == "" {
		logger.Printf("debug event=sigv4_verify_failure stage=%q method=%q path=%q raw_query=%q host=%q scheme=%q access_key=%q scope=%q signed_headers=%q error=%q", "time", r.Method, r.URL.Path, r.URL.RawQuery, r.Host, r.URL.Scheme, auth.accessKey, auth.date+"/"+auth.region+"/"+auth.service+"/aws4_request", strings.Join(auth.signedHeaders, ";"), "missing x-amz-date")
		return Identity{}, ErrSignatureDoesNotMatch
	}
	if auth.presigned {
		if err := v.validatePresignedRequestTime(auth.xAmzDate, auth.date, auth.expires); err != nil {
			logger.Printf("debug event=sigv4_verify_failure stage=%q method=%q path=%q raw_query=%q host=%q scheme=%q access_key=%q x_amz_date=%q scope=%q signed_headers=%q expires=%v error=%q", "time", r.Method, r.URL.Path, r.URL.RawQuery, r.Host, r.URL.Scheme, auth.accessKey, auth.xAmzDate, auth.date+"/"+auth.region+"/"+auth.service+"/aws4_request", strings.Join(auth.signedHeaders, ";"), auth.expires, sanitizeLogError(err))
			return Identity{}, ErrSignatureDoesNotMatch
		}
	} else if err := v.validateRequestTime(auth.xAmzDate, auth.date); err != nil {
		logger.Printf("debug event=sigv4_verify_failure stage=%q method=%q path=%q raw_query=%q host=%q scheme=%q access_key=%q x_amz_date=%q scope=%q signed_headers=%q error=%q", "time", r.Method, r.URL.Path, r.URL.RawQuery, r.Host, r.URL.Scheme, auth.accessKey, auth.xAmzDate, auth.date+"/"+auth.region+"/"+auth.service+"/aws4_request", strings.Join(auth.signedHeaders, ";"), sanitizeLogError(err))
		return Identity{}, ErrSignatureDoesNotMatch
	}

	canonicalPayloadHash := "UNSIGNED-PAYLOAD"
	if !auth.presigned {
		canonicalPayloadHash, err = payloadHash(r)
		if err != nil {
			logger.Printf("debug event=sigv4_verify_failure stage=%q method=%q path=%q raw_query=%q host=%q scheme=%q access_key=%q x_amz_date=%q scope=%q signed_headers=%q error=%q", "payload", r.Method, r.URL.Path, r.URL.RawQuery, r.Host, r.URL.Scheme, auth.accessKey, auth.xAmzDate, auth.date+"/"+auth.region+"/"+auth.service+"/aws4_request", strings.Join(auth.signedHeaders, ";"), sanitizeLogError(err))
			return Identity{}, ErrSignatureDoesNotMatch
		}
	}

	canonicalRequest, err := buildCanonicalRequest(r, auth.signedHeaders, canonicalPayloadHash, auth.presigned)
	if err != nil {
		logger.Printf("debug event=sigv4_verify_failure stage=%q method=%q path=%q raw_query=%q host=%q scheme=%q access_key=%q x_amz_date=%q scope=%q signed_headers=%q payload_hash=%q error=%q", "canonical", r.Method, r.URL.Path, r.URL.RawQuery, r.Host, r.URL.Scheme, auth.accessKey, auth.xAmzDate, auth.date+"/"+auth.region+"/"+auth.service+"/aws4_request", strings.Join(auth.signedHeaders, ";"), canonicalPayloadHash, sanitizeLogError(err))
		return Identity{}, ErrSignatureDoesNotMatch
	}

	credentialScope := strings.Join([]string{auth.date, auth.region, auth.service, "aws4_request"}, "/")
	canonicalRequestHash := hexSHA256(canonicalRequest)
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		auth.xAmzDate,
		credentialScope,
		canonicalRequestHash,
	}, "\n")

	signingKey := deriveSigningKey(secret, auth.date, auth.region, auth.service)
	expectedSignature := hex.EncodeToString(hmacSHA256(signingKey, stringToSign))

	matched := subtle.ConstantTimeCompare([]byte(expectedSignature), []byte(auth.signature)) == 1
	if !matched && fallbackAcceptedByRewrittenAcceptEncoding(r, auth.signedHeaders, auth.signature, signingKey, auth.xAmzDate, credentialScope, canonicalPayloadHash, auth.presigned) {
		matched = true
		logger.Printf("debug event=sigv4_accept_encoding_fallback method=%q path=%q raw_query=%q host=%q scheme=%q access_key=%q", r.Method, r.URL.Path, r.URL.RawQuery, r.Host, r.URL.Scheme, auth.accessKey)
	}
	if !matched {
		logger.Printf("debug event=sigv4_verify_failure stage=%q method=%q path=%q raw_query=%q host=%q scheme=%q access_key=%q x_amz_date=%q scope=%q signed_headers=%q payload_hash=%q signed_header_value_hashes=%q canonical_request_hash=%q", "signature", r.Method, r.URL.Path, r.URL.RawQuery, r.Host, r.URL.Scheme, auth.accessKey, auth.xAmzDate, credentialScope, strings.Join(auth.signedHeaders, ";"), canonicalPayloadHash, signedHeaderValueHashes(r, auth.signedHeaders), canonicalRequestHash)
		return Identity{}, ErrSignatureDoesNotMatch
	}

	// The seed (Authorization header) signature is confirmed. If the
	// payload was transferred as aws-chunked, swap r.Body for a reader
	// that verifies each chunk's signature against the previous one and
	// yields the decoded payload bytes, and correct r.ContentLength to
	// the true decoded size. Downstream handlers (putObject, uploadPart)
	// then see a normal, verified, correctly-sized body.
	if isStreamingPayloadHash(canonicalPayloadHash) {
		if err := attachChunkedBody(r, canonicalPayloadHash, signingKey, credentialScope, auth.xAmzDate, auth.signature); err != nil {
			logger.Printf("debug event=sigv4_verify_failure stage=%q method=%q path=%q error=%q", "chunked_body", r.Method, r.URL.Path, sanitizeLogError(err))
			return Identity{}, ErrSignatureDoesNotMatch
		}
	}

	return Identity{AccessKey: auth.accessKey, Presigned: auth.presigned}, nil
}

func fallbackAcceptedByRewrittenAcceptEncoding(r *http.Request, signedHeaders []string, signature string, signingKey []byte, xAmzDate, credentialScope, canonicalPayloadHash string, presigned bool) bool {
	if r.Header.Get("Accept-Encoding") == "" {
		return false
	}
	for _, header := range signedHeaders {
		if strings.EqualFold(strings.TrimSpace(header), "accept-encoding") {
			for _, fallbackValue := range []string{"identity", "gzip"} {
				fallbackRequest := cloneRequestWithHeader(r, "Accept-Encoding", fallbackValue)
				fallbackCanonicalRequest, err := buildCanonicalRequest(fallbackRequest, signedHeaders, canonicalPayloadHash, presigned)
				if err != nil {
					continue
				}
				fallbackStringToSign := strings.Join([]string{
					"AWS4-HMAC-SHA256",
					xAmzDate,
					credentialScope,
					hexSHA256(fallbackCanonicalRequest),
				}, "\n")
				fallbackSignature := hex.EncodeToString(hmacSHA256(signingKey, fallbackStringToSign))
				if subtle.ConstantTimeCompare([]byte(fallbackSignature), []byte(signature)) == 1 {
					return true
				}
			}
			return false
		}
	}
	return false
}

func cloneRequestWithHeader(r *http.Request, name, value string) *http.Request {
	clone := r.Clone(r.Context())
	clone.Header = r.Header.Clone()
	clone.Header.Set(name, value)
	return clone
}

func (v *SigV4Verifier) validateRequestTime(xAmzDate, scopeDate string) error {
	signedAt, err := time.Parse("20060102T150405Z", xAmzDate)
	if err != nil {
		return err
	}
	if scopeDate != signedAt.UTC().Format("20060102") {
		return fmt.Errorf("credential scope date does not match request timestamp")
	}
	if v.maxSkew <= 0 {
		return nil
	}
	now := v.clock().UTC()
	if signedAt.Before(now.Add(-v.maxSkew)) || signedAt.After(now.Add(v.maxSkew)) {
		return fmt.Errorf("request timestamp outside allowed skew")
	}
	return nil
}

func (v *SigV4Verifier) validatePresignedRequestTime(xAmzDate, scopeDate string, expires time.Duration) error {
	signedAt, err := time.Parse("20060102T150405Z", xAmzDate)
	if err != nil {
		return err
	}
	if scopeDate != signedAt.UTC().Format("20060102") {
		return fmt.Errorf("credential scope date does not match request timestamp")
	}
	now := v.clock().UTC()
	if v.maxSkew > 0 && signedAt.After(now.Add(v.maxSkew)) {
		return fmt.Errorf("request timestamp outside allowed skew")
	}
	if now.After(signedAt.Add(expires)) {
		return fmt.Errorf("request expired")
	}
	return nil
}

func parseSigV4RequestAuth(r *http.Request) (sigV4Authorization, error) {
	if header := r.Header.Get("Authorization"); header != "" {
		auth, err := parseSigV4Authorization(header)
		if err != nil {
			return sigV4Authorization{}, err
		}
		auth.xAmzDate = r.Header.Get("X-Amz-Date")
		return auth, nil
	}
	return parseSigV4QueryAuthorization(r.URL.Query())
}

func parseSigV4Authorization(header string) (sigV4Authorization, error) {
	const prefix = "AWS4-HMAC-SHA256 "
	if !strings.HasPrefix(header, prefix) {
		return sigV4Authorization{}, fmt.Errorf("invalid authorization scheme")
	}

	parts := strings.Split(header[len(prefix):], ",")
	values := make(map[string]string, len(parts))
	for _, part := range parts {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || value == "" {
			return sigV4Authorization{}, fmt.Errorf("invalid authorization field")
		}
		values[key] = value
	}

	credentialParts := strings.Split(values["Credential"], "/")
	if len(credentialParts) != 5 || credentialParts[4] != "aws4_request" {
		return sigV4Authorization{}, fmt.Errorf("invalid credential scope")
	}

	signedHeaders := strings.Split(values["SignedHeaders"], ";")
	if len(signedHeaders) == 0 || signedHeaders[0] == "" || values["Signature"] == "" {
		return sigV4Authorization{}, fmt.Errorf("missing authorization fields")
	}

	return sigV4Authorization{
		accessKey:     credentialParts[0],
		date:          credentialParts[1],
		region:        credentialParts[2],
		service:       credentialParts[3],
		signedHeaders: signedHeaders,
		signature:     strings.ToLower(values["Signature"]),
	}, nil
}

func parseSigV4QueryAuthorization(values url.Values) (sigV4Authorization, error) {
	if values.Get("X-Amz-Algorithm") != "AWS4-HMAC-SHA256" {
		return sigV4Authorization{}, fmt.Errorf("invalid authorization scheme")
	}

	credential := values.Get("X-Amz-Credential")
	xAmzDate := values.Get("X-Amz-Date")
	expiresValue := values.Get("X-Amz-Expires")
	signedHeadersValue := values.Get("X-Amz-SignedHeaders")
	signature := values.Get("X-Amz-Signature")
	if credential == "" || xAmzDate == "" || expiresValue == "" || signedHeadersValue == "" || signature == "" {
		return sigV4Authorization{}, fmt.Errorf("missing authorization fields")
	}

	credentialParts := strings.Split(credential, "/")
	if len(credentialParts) != 5 || credentialParts[4] != "aws4_request" {
		return sigV4Authorization{}, fmt.Errorf("invalid credential scope")
	}

	expiresSeconds, err := time.ParseDuration(expiresValue + "s")
	if err != nil {
		return sigV4Authorization{}, fmt.Errorf("invalid expires")
	}
	if expiresSeconds <= 0 || expiresSeconds > 7*24*time.Hour {
		return sigV4Authorization{}, fmt.Errorf("invalid expires")
	}

	signedHeaders := strings.Split(signedHeadersValue, ";")
	if len(signedHeaders) == 0 || signedHeaders[0] == "" {
		return sigV4Authorization{}, fmt.Errorf("missing signed headers")
	}

	return sigV4Authorization{
		accessKey:     credentialParts[0],
		date:          credentialParts[1],
		region:        credentialParts[2],
		service:       credentialParts[3],
		signedHeaders: signedHeaders,
		signature:     strings.ToLower(signature),
		xAmzDate:      xAmzDate,
		expires:       expiresSeconds,
		presigned:     true,
	}, nil
}

func payloadHash(r *http.Request) (string, error) {
	hash := r.Header.Get("X-Amz-Content-Sha256")
	if hash == "" {
		if r.Body == nil || r.Body == http.NoBody {
			return EmptyPayloadSHA256, nil
		}
		return "", fmt.Errorf("missing payload hash")
	}
	if hash == "UNSIGNED-PAYLOAD" {
		return hash, nil
	}
	if isStreamingPayloadHash(hash) {
		// The canonical request uses this literal token as the payload
		// hash placeholder rather than an actual digest of the (chunked,
		// framed) wire bytes. Per-chunk signatures are verified
		// separately, after the seed signature check succeeds -- see
		// attachChunkedBody.
		return hash, nil
	}
	if r.Body == nil || r.Body == http.NoBody {
		if hash != EmptyPayloadSHA256 {
			return "", fmt.Errorf("payload hash mismatch")
		}
		return hash, nil
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return "", fmt.Errorf("read body: %w", err)
	}
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(body))

	actual := sha256.Sum256(body)
	if hex.EncodeToString(actual[:]) != strings.ToLower(hash) {
		return "", fmt.Errorf("payload hash mismatch")
	}
	return strings.ToLower(hash), nil
}

func buildCanonicalRequest(r *http.Request, signedHeaders []string, payloadHash string, excludeSignatureQuery bool) (string, error) {
	canonicalHeaders, signedHeaderList, err := canonicalHeaders(r, signedHeaders)
	if err != nil {
		return "", err
	}

	return strings.Join([]string{
		r.Method,
		canonicalURI(r.URL),
		canonicalQueryString(r.URL, excludeSignatureQuery),
		canonicalHeaders,
		signedHeaderList,
		payloadHash,
	}, "\n"), nil
}

func canonicalURI(u *url.URL) string {
	// Use u.EscapedPath() verbatim, with no further decode/re-encode pass.
	// A spec-compliant SigV4 client (rclone, aws-cli, mc, the AWS SDKs) signs
	// using the exact same percent-encoded path bytes it then places on the
	// wire, so the server's canonical URI must be that same wire
	// representation, not an independently re-derived encoding.
	//
	// A prior implementation split u.Path (already unescaped by Go) on
	// "/" and ran each segment through a re-encoder, which broke in two
	// different ways depending on the input:
	//   - For an already-escaped path with no special segment separators
	//     (e.g. accented UTF-8 bytes), the re-encoder re-encoded the literal
	//     "%" from Go's prior escaping, double-encoding it and diverging
	//     from what the client signed (403 SignatureDoesNotMatch).
	//   - For a path containing a meaningfully escaped "/" inside a single
	//     object key (e.g. "a%2Fb.txt", a literal slash in the key, not a
	//     path separator), decoding via u.Path turned it into an extra path
	//     segment ("a", "b.txt"), losing that distinction entirely.
	// Using the untouched wire bytes avoids both failure modes.
	path := u.EscapedPath()
	if path == "" {
		return "/"
	}
	return path
}

func canonicalQueryString(u *url.URL, excludeSignature bool) string {
	if u.RawQuery == "" {
		return ""
	}

	type pair struct {
		key   string
		value string
	}

	tokens := strings.Split(u.RawQuery, "&")
	pairs := make([]pair, 0, len(tokens))
	for _, token := range tokens {
		key, value, hasValue := strings.Cut(token, "=")
		if !hasValue {
			value = ""
		}
		if excludeSignature && canonicalQueryComponent(key) == "X-Amz-Signature" {
			continue
		}
		pairs = append(pairs, pair{
			key:   canonicalQueryComponent(key),
			value: canonicalQueryComponent(value),
		})
	}

	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].key == pairs[j].key {
			return pairs[i].value < pairs[j].value
		}
		return pairs[i].key < pairs[j].key
	})

	encoded := make([]string, 0, len(pairs))
	for _, item := range pairs {
		encoded = append(encoded, item.key+"="+item.value)
	}
	return strings.Join(encoded, "&")
}

func canonicalQueryComponent(raw string) string {
	decoded := make([]byte, 0, len(raw))
	for i := 0; i < len(raw); i++ {
		if raw[i] == '%' && i+2 < len(raw) {
			hi, okHi := fromHex(raw[i+1])
			lo, okLo := fromHex(raw[i+2])
			if okHi && okLo {
				decoded = append(decoded, hi<<4|lo)
				i += 2
				continue
			}
		}
		decoded = append(decoded, raw[i])
	}
	return sigV4Encode(string(decoded), true)
}

func fromHex(b byte) (byte, bool) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', true
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10, true
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10, true
	default:
		return 0, false
	}
}

func canonicalHeaders(r *http.Request, signedHeaders []string) (string, string, error) {
	normalizedHeaders := make([]string, 0, len(signedHeaders))
	seen := make(map[string]struct{}, len(signedHeaders))
	for _, header := range signedHeaders {
		name := strings.ToLower(strings.TrimSpace(header))
		if name == "" {
			return "", "", fmt.Errorf("empty signed header")
		}
		if _, ok := seen[name]; ok {
			return "", "", fmt.Errorf("duplicate signed header")
		}
		seen[name] = struct{}{}
		normalizedHeaders = append(normalizedHeaders, name)
	}

	sort.Strings(normalizedHeaders)

	canonical := make([]string, 0, len(normalizedHeaders))
	for _, name := range normalizedHeaders {
		value, ok := headerValue(r, name)
		if !ok {
			return "", "", fmt.Errorf("missing signed header")
		}
		canonical = append(canonical, name+":"+normalizeHeaderValue(value))
	}

	return strings.Join(canonical, "\n") + "\n", strings.Join(normalizedHeaders, ";"), nil
}

func signedHeaderValueHashes(r *http.Request, signedHeaders []string) string {
	names := make([]string, 0, len(signedHeaders))
	seen := make(map[string]struct{}, len(signedHeaders))
	for _, header := range signedHeaders {
		name := strings.ToLower(strings.TrimSpace(header))
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	sort.Strings(names)

	parts := make([]string, 0, len(names))
	for _, name := range names {
		value, ok := headerValue(r, name)
		if !ok {
			parts = append(parts, name+":missing")
			continue
		}
		parts = append(parts, name+":"+hexSHA256(normalizeHeaderValue(value)))
	}
	return strings.Join(parts, ";")
}

func headerValue(r *http.Request, name string) (string, bool) {
	switch name {
	case "host":
		if r.Host != "" {
			return r.Host, true
		}
		if r.URL.Host != "" {
			return r.URL.Host, true
		}
		return "", false
	case "content-length":
		if len(r.Header.Values("Content-Length")) > 0 {
			break
		}
		if r.ContentLength >= 0 {
			return fmt.Sprintf("%d", r.ContentLength), true
		}
	}
	values := r.Header.Values(http.CanonicalHeaderKey(name))
	if len(values) == 0 {
		return "", false
	}
	return strings.Join(values, ","), true
}

func normalizeHeaderValue(value string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(value)), " ")
}

func deriveSigningKey(secret, date, region, service string) []byte {
	dateKey := hmacSHA256([]byte("AWS4"+secret), date)
	regionKey := hmacSHA256(dateKey, region)
	serviceKey := hmacSHA256(regionKey, service)
	return hmacSHA256(serviceKey, "aws4_request")
}

func hmacSHA256(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(data))
	return mac.Sum(nil)
}

func hexSHA256(data string) string {
	sum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sum[:])
}

func sigV4Encode(s string, encodeSlash bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
			continue
		}
		if c == '/' && !encodeSlash {
			b.WriteByte(c)
			continue
		}
		b.WriteString(fmt.Sprintf("%%%02X", c))
	}
	return b.String()
}

// --- aws-chunked (streaming SigV4) support ---
//
// When a client signs a request with X-Amz-Content-Sha256:
// STREAMING-AWS4-HMAC-SHA256-PAYLOAD (or the -TRAILER variant), the body
// is not a single hashed payload -- it's transferred as a sequence of
// chunks, each framed and individually signed:
//
//   <hex-chunk-size>;chunk-signature=<hex-sig>\r\n
//   <chunk-size bytes of raw data>\r\n
//   ... (repeated) ...
//   0;chunk-signature=<hex-sig>\r\n
//   [optional trailer headers]\r\n
//   \r\n
//
// Each chunk's signature is derived from the previous chunk's signature
// (the very first chunk chains off the seed/Authorization-header
// signature), which is why this can only run after that seed signature
// has already been confirmed.

// maxChunkSize guards against a malformed or malicious chunk-size field
// forcing an unbounded allocation. AWS SDKs typically chunk in the
// 64KiB-8MiB range; this leaves generous headroom.
const maxChunkSize = 64 << 20 // 64 MiB

// attachChunkedBody replaces r.Body with a reader that verifies and
// decodes an aws-chunked signed payload, and corrects r.ContentLength to
// the true decoded object size (taken from X-Amz-Decoded-Content-Length,
// which clients are required to send for chunked uploads). It must only
// be called after the seed (Authorization header) signature has already
// been verified, since seedSignature anchors the first chunk's signature
// chain.
func attachChunkedBody(r *http.Request, payloadHash string, signingKey []byte, scope, timestamp, seedSignature string) error {
	if r.Body == nil || r.Body == http.NoBody {
		return fmt.Errorf("missing chunked body")
	}
	decodedLength, err := decodedContentLength(r)
	if err != nil {
		return err
	}
	trailer := payloadHash == StreamingPayloadSHA256Trailer
	reader := newChunkedPayloadReader(r.Body, signingKey, scope, timestamp, strings.ToLower(seedSignature), trailer)
	r.Body = io.NopCloser(reader)
	r.ContentLength = decodedLength
	return nil
}

func decodedContentLength(r *http.Request) (int64, error) {
	value := r.Header.Get("X-Amz-Decoded-Content-Length")
	if value == "" {
		return 0, fmt.Errorf("missing x-amz-decoded-content-length")
	}
	length, err := strconv.ParseInt(value, 10, 64)
	if err != nil || length < 0 {
		return 0, fmt.Errorf("invalid x-amz-decoded-content-length")
	}
	return length, nil
}

// chunkedPayloadReader decodes an aws-chunked request body into raw
// payload bytes, verifying each chunk's signature against the previous
// chunk's signature (per the AWS SigV4 streaming spec) as it goes. A
// signature mismatch on any chunk, or malformed chunk framing, surfaces
// as a Read error, which callers (payload consumers) should treat the
// same as any other body read failure.
type chunkedPayloadReader struct {
	buf           *bufio.Reader
	signingKey    []byte
	scope         string
	timestamp     string
	trailer       bool
	prevSignature string
	pending       []byte
	pendingPos    int
	done          bool
}

func newChunkedPayloadReader(body io.Reader, signingKey []byte, scope, timestamp, seedSignature string, trailer bool) *chunkedPayloadReader {
	return &chunkedPayloadReader{
		buf:           bufio.NewReader(body),
		signingKey:    signingKey,
		scope:         scope,
		timestamp:     timestamp,
		trailer:       trailer,
		prevSignature: seedSignature,
	}
}

func (c *chunkedPayloadReader) Read(p []byte) (int, error) {
	for c.pendingPos >= len(c.pending) {
		if c.done {
			return 0, io.EOF
		}
		if err := c.readNextChunk(); err != nil {
			c.done = true
			return 0, err
		}
	}
	n := copy(p, c.pending[c.pendingPos:])
	c.pendingPos += n
	return n, nil
}

// readNextChunk reads, verifies, and buffers one chunk into c.pending.
// On the final (zero-length) chunk it verifies its signature (and
// consumes any trailer), then returns io.EOF. On any framing or
// signature failure it returns a descriptive, non-EOF error.
func (c *chunkedPayloadReader) readNextChunk() error {
	header, err := c.buf.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read chunk header: %w", err)
	}
	header = strings.TrimRight(header, "\r\n")
	sizeField, sigField, ok := strings.Cut(header, ";")
	if !ok {
		return fmt.Errorf("malformed chunk header")
	}
	chunkSize, err := strconv.ParseInt(strings.TrimSpace(sizeField), 16, 64)
	if err != nil || chunkSize < 0 || chunkSize > maxChunkSize {
		return fmt.Errorf("malformed or oversized chunk size")
	}
	sigKey, sigValue, ok := strings.Cut(strings.TrimSpace(sigField), "=")
	if !ok || sigKey != "chunk-signature" || sigValue == "" {
		return fmt.Errorf("malformed chunk signature")
	}
	chunkSignature := strings.ToLower(sigValue)

	data := make([]byte, chunkSize)
	if chunkSize > 0 {
		if _, err := io.ReadFull(c.buf, data); err != nil {
			return fmt.Errorf("read chunk data: %w", err)
		}
	}
	if cr, err := c.buf.ReadByte(); err != nil || cr != '\r' {
		return fmt.Errorf("malformed chunk terminator")
	}
	if lf, err := c.buf.ReadByte(); err != nil || lf != '\n' {
		return fmt.Errorf("malformed chunk terminator")
	}

	chunkDataHash := hexSHA256(string(data))
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256-PAYLOAD",
		c.timestamp,
		c.scope,
		c.prevSignature,
		EmptyPayloadSHA256,
		chunkDataHash,
	}, "\n")
	expectedSignature := hex.EncodeToString(hmacSHA256(c.signingKey, stringToSign))
	if subtle.ConstantTimeCompare([]byte(expectedSignature), []byte(chunkSignature)) != 1 {
		return fmt.Errorf("chunk signature mismatch")
	}
	c.prevSignature = chunkSignature

	if chunkSize == 0 {
		if c.trailer {
			if err := c.consumeTrailer(); err != nil {
				return err
			}
		}
		return io.EOF
	}

	c.pending = data
	c.pendingPos = 0
	return nil
}

// consumeTrailer reads and discards trailer header lines up to the
// terminating blank line. Trailer checksum values (e.g.
// x-amz-checksum-crc32) are not currently independently verified.
func (c *chunkedPayloadReader) consumeTrailer() error {
	for {
		line, err := c.buf.ReadString('\n')
		if err != nil {
			return fmt.Errorf("read trailer: %w", err)
		}
		if strings.TrimRight(line, "\r\n") == "" {
			return nil
		}
	}
}