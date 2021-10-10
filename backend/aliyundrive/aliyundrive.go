package aliyundrive

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/config/configstruct"
	"github.com/rclone/rclone/fs/fserrors"
	"github.com/rclone/rclone/fs/fshttp"
	"github.com/rclone/rclone/fs/hash"
	"github.com/rclone/rclone/lib/dircache"
	"github.com/rclone/rclone/lib/encoder"
	"github.com/rclone/rclone/lib/pacer"
	"github.com/rclone/rclone/lib/rest"
)

const (
	apiEndpointDefault          = "https://api.aliyundrive.com/v2"
	apiEntryListFile            = "/file/list"
	apiEntryGetFile             = "/file/get"
	apiEntrySearchFile          = "/file/search"
	apiEntryDeleteFile          = "/file/delete"
	apiEntryCopyFile            = "/file/copy"
	apiEntryMoveFile            = "/file/move"
	apiEntryCreateFile          = "/file/create"
	apiEntryCreateFileWithProof = "/file/create_with_proof"
	apiEntryGetFileUrl          = "/file/get_download_url"
	apiEntryDownloadFile        = "/file/download"
	apiEntryComplete            = "/file/complete"

	apiEndpointAuth = "https://auth.aliyundrive.com/v2"
	apiEntryToken   = "/account/token"

	preHashBytesSize = 1024
	uploadPartSize   = 1024 * 1024 * 20 //20MB

	minSleep      = 10 * time.Millisecond
	maxSleep      = 5 * time.Minute
	decayConstant = 1 // bigger for slower decay, exponential
)

var (
	commonHeaders = map[string]string{
		"Referer":    "https://www.aliyundrive.com/",
		"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36",
	}
)

// Options defines the configuration for this backend
type Options struct {
	RefreshToken string               `config:"refresh_token"`
	Enc          encoder.MultiEncoder `config:"encoding"`
}

// Fs represents a remote Aliyundrive server
type Fs struct {
	name     string             // name of this remote
	root     string             // the path we are working on if any
	opt      Options            // parsed options
	features *fs.Features       // optional features
	srv      *rest.Client       // the connection to the server
	pacer    *fs.Pacer          // pacer for server connections
	session  Session            // connection session
	dirCache *dircache.DirCache // Map of directory path to directory id
}

type Object struct {
	fs       *Fs       // what this object is part of
	remote   string    // The remote path
	id       string    // ID of the file
	parentId string    // ID of the parent directory
	modTime  time.Time // The modified time of the object if known
	hash     string    // SHA1 hash if known
	size     int64     // Size of the object
}

// Fs returns the parent Fs
func (o *Object) Fs() fs.Info {
	return o.fs
}

// Return a string version
func (o *Object) String() string {
	if o == nil {
		return "<nil>"
	}
	return o.remote
}

// Remote returns the remote path
func (o *Object) Remote() string {
	return o.remote
}

// Hash returns the Md5sum of an object returning a lowercase hex string
func (o *Object) Hash(ctx context.Context, t hash.Type) (string, error) {
	if t != hash.SHA1 {
		return "", hash.ErrUnsupported
	}
	return strings.ToLower(o.hash), nil
}

// Size returns the size of an object in bytes
func (o *Object) Size() int64 {
	return o.size // Object is likely PENDING
}

func (o *Object) ModTime(ctx context.Context) time.Time {
	return o.modTime
}

func (o *Object) readMetaData(ctx context.Context) (err error) {
	var leafItem *BasePDSFileResponse
	if o.id != "" {
		leafItem, err = o.fs.pdsGetFileMeta(ctx, o.id)
		if err != nil {
			return err
		}
	} else {
		leaf, directoryID, err := o.fs.dirCache.FindPath(ctx, o.remote, false)
		if err != nil {
			if err == fs.ErrorDirNotFound {
				return fs.ErrorObjectNotFound
			}
			return err
		}

		query := fmt.Sprintf("parent_file_id = \"%s\" and name = \"%s\"", directoryID, leaf)
		items, err := o.fs.pdsSearch(ctx, query)
		if err != nil {
			return err
		}
		if err == nil && len(items) == 0 {
			return fs.ErrorObjectNotFound
		}

		leafItem = &items[0]
	}

	o.id = leafItem.FileId
	o.parentId = leafItem.ParentFileId
	o.hash = leafItem.Hash
	o.size = leafItem.Size

	if mTime, err := leafItem.GetTime(); err == nil {
		o.modTime = mTime
	} else {
		return err
	}

	return
}

func (o *Object) Open(ctx context.Context, options ...fs.OpenOption) (in io.ReadCloser, err error) {
	fs.FixRangeOption(options, o.size)
	return o.fs.pdsGetFile(ctx, o.id, options...)
}

func (o *Object) Update(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) error {
	size := src.Size()
	remote := o.Remote()
	hash, err := src.Hash(ctx, hash.SHA1)
	if err != nil {
		hash = ""
	}

	if size < 0 {
		return errors.New("can't upload unknown sizes objects")
	}

	// Create the directory for the object if it doesn't exist
	leaf, directoryID, err := o.fs.dirCache.FindPath(ctx, remote, true)
	if err != nil {
		return err
	}

	o.id, err = o.fs.pdsUpload(ctx, directoryID, leaf, size, hash, in, options...)
	if err != nil {
		return err
	}
	o.readMetaData(ctx)
	return err
}

func (o *Object) Remove(ctx context.Context) error {
	return o.fs.pdsRemove(ctx, o.id)
}

func (o *Object) SetModTime(ctx context.Context, modTime time.Time) error {
	return fs.ErrorCantSetModTime
}

func (o *Object) Storable() bool {
	return true
}

// Name of the remote (as passed into NewFs)
func (f *Fs) Name() string {
	return f.name
}

// Root of the remote (as passed into NewFs)
func (f *Fs) Root() string {
	return f.root
}

// String converts this Fs to a string
func (f *Fs) String() string {
	return fmt.Sprintf("AliyunDrive '%s'", f.name)
}

// Features returns the optional features of this Fs
func (f *Fs) Features() *fs.Features {
	return f.features
}

// Hashes returns the supported hash sets.
func (f *Fs) Hashes() hash.Set {
	return hash.Set(hash.SHA1)
}

func (f *Fs) Precision() time.Duration {
	return time.Second
}

func CalcProof(accessToken string, size int64, in io.ReadSeeker) (string, error) {
	md5Bytes := md5.Sum([]byte(accessToken))
	startIdx := int64(binary.BigEndian.Uint64(md5Bytes[:8]) % uint64(size))

	in.Seek(startIdx, io.SeekStart)
	proofBytes := make([]byte, 8)
	in.Read(proofBytes)
	proofCode := base64.StdEncoding.EncodeToString(proofBytes)
	in.Seek(0, 0)

	return proofCode, nil
}

func CalcSHA1(size int64, in io.ReadSeeker) (string, error) {
	fileBytes := make([]byte, size)

	in.Seek(0, io.SeekStart)
	if n, err := in.Read(fileBytes); err != nil || n != int(size) {
		return "", errors.Wrap(err, "failed to calculate content hash")
	}
	in.Seek(0, io.SeekStart)

	return fmt.Sprintf("%X", sha1.Sum(fileBytes)), nil
}

func makePartInfoList(size int64) []UploadPartInfo {
	totalParts := (size + uploadPartSize - 1) / uploadPartSize
	partInfoList := make([]UploadPartInfo, totalParts)
	for i := int64(0); i < totalParts; i++ {
		partInfoList[i] = UploadPartInfo{
			PartNumber: i + 1,
		}
	}
	return partInfoList
}

func (s *Session) Headers() map[string]string {
	headers := map[string]string{
		"content-type":  "application/json;charset=UTF-8",
		"authorization": "Bearer " + s.AccessToken,
	}
	return headers
}

func (r *BasePDSFileResponse) GetTime() (time.Time, error) {
	layout := "2006-01-02T15:04:05.000Z"
	t, err := time.Parse(layout, r.UpdatedAt)

	if err != nil {
		return time.Time{}, err
	}
	return t, nil
}

func (r *PDSListFileRequest) GetMarker() string       { return r.Marker }
func (r *PDSListFileRequest) GetLimit() int64         { return r.Limit }
func (r *PDSListFileRequest) SetMarker(marker string) { r.Marker = marker }
func (r *PDSListFileRequest) SetLimit(limit int64)    { r.Limit = limit }

func (r *PDSSearchFileRequest) GetMarker() string       { return r.Marker }
func (r *PDSSearchFileRequest) GetLimit() int64         { return r.Limit }
func (r *PDSSearchFileRequest) SetMarker(marker string) { r.Marker = marker }
func (r *PDSSearchFileRequest) SetLimit(limit int64)    { r.Limit = limit }

// Register with Fs
func init() {
	fs.Register(&fs.RegInfo{
		Name:        "aliyundrive",
		Description: "AliyunDrive",
		NewFs:       NewFs,
		Options: []fs.Option{
			{
				Name:     "refresh_token",
				Help:     "Refresh Token",
				Required: true,
			}, {
				Name:     config.ConfigEncoding,
				Help:     config.ConfigEncodingHelp,
				Advanced: true,
				// List of replaced characters:
				//   < (less than)     -> '＜' // FULLWIDTH LESS-THAN SIGN
				//   > (greater than)  -> '＞' // FULLWIDTH GREATER-THAN SIGN
				//   : (colon)         -> '：' // FULLWIDTH COLON
				//   " (double quote)  -> '＂' // FULLWIDTH QUOTATION MARK
				//   \ (backslash)     -> '＼' // FULLWIDTH REVERSE SOLIDUS
				//   | (vertical line) -> '｜' // FULLWIDTH VERTICAL LINE
				//   ? (question mark) -> '？' // FULLWIDTH QUESTION MARK
				//   * (asterisk)      -> '＊' // FULLWIDTH ASTERISK
				//
				// Additionally names can't begin or end with an ASCII whitespace.
				// List of replaced characters:
				//     (space)           -> '␠'  // SYMBOL FOR SPACE
				//     (horizontal tab)  -> '␉'  // SYMBOL FOR HORIZONTAL TABULATION
				//     (line feed)       -> '␊'  // SYMBOL FOR LINE FEED
				//     (vertical tab)    -> '␋'  // SYMBOL FOR VERTICAL TABULATION
				//     (carriage return) -> '␍'  // SYMBOL FOR CARRIAGE RETURN
				//
				// Also encode invalid UTF-8 bytes as json doesn't handle them properly.
				//
				// https://www.opendrive.com/wp-content/uploads/guides/OpenDrive_API_guide.pdf
				Default: (encoder.Base |
					encoder.EncodeWin |
					encoder.EncodeLeftCrLfHtVt |
					encoder.EncodeRightCrLfHtVt |
					encoder.EncodeBackSlash |
					encoder.EncodeLeftSpace |
					encoder.EncodeRightSpace |
					encoder.EncodeInvalidUtf8),
			},
		},
	})
}

// NewFs constructs an Fs from the path
func NewFs(ctx context.Context, name, root string, m configmap.Mapper) (fs.Fs, error) {
	// Parse config into Options struct
	opt := new(Options)
	err := configstruct.Set(m, opt)
	if err != nil {
		return nil, err
	}

	if opt.RefreshToken == "" {
		return nil, errors.New("refresh token not found")
	}

	f := &Fs{
		name:  name,
		root:  root,
		opt:   *opt,
		srv:   rest.NewClient(fshttp.NewClient(ctx)),
		pacer: fs.NewPacer(ctx, pacer.NewDefault(pacer.MinSleep(minSleep), pacer.MaxSleep(maxSleep), pacer.DecayConstant(decayConstant))),
	}

	f.dirCache = dircache.New(root, "root", f)

	// set the rootURL for the REST client
	f.srv.SetRoot(apiEndpointDefault)
	for k, v := range commonHeaders {
		f.srv.SetHeader(k, v)
	}

	// get session
	err = f.refreshSession(ctx, m)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create session")
	}

	f.features = (&fs.Features{
		CaseInsensitive:         false,
		CanHaveEmptyDirectories: true,
	}).Fill(ctx, f)

	err = f.dirCache.FindRoot(ctx, false)
	if err != nil {
		// Assume it is a file
		newRoot, remote := dircache.SplitPath(root)
		tempF := *f
		tempF.dirCache = dircache.New(newRoot, "root", &tempF)
		tempF.root = newRoot

		// Make new Fs which is the parent
		err = tempF.dirCache.FindRoot(ctx, false)
		if err != nil {
			// No root so return old f
			return f, nil
		}
		_, err := tempF.newObjectWithInfo(ctx, remote, nil)
		if err != nil {
			if err == fs.ErrorObjectNotFound {
				// File doesn't exist so return old f
				f.dirCache = tempF.dirCache
				f.root = tempF.root
				return f, nil
			}
			return nil, err
		}
		// XXX: update the old f here instead of returning tempF, since
		// `features` were already filled with functions having *f as a receiver.
		// See https://github.com/rclone/rclone/issues/2182
		f.dirCache = tempF.dirCache
		f.root = tempF.root
		// return an error with an fs which points to the parent
		return f, fs.ErrorIsFile
	}

	return f, nil
}

func (f *Fs) refreshSession(ctx context.Context, m configmap.Mapper) error {
	err := f.pacer.Call(func() (bool, error) {
		reqBody := map[string]string{
			"refresh_token": f.opt.RefreshToken,
			"grant_type":    "refresh_token",
		}
		opts := rest.Opts{
			Method:      "POST",
			RootURL:     apiEndpointAuth,
			Path:        apiEntryToken,
			ContentType: "application/json;charset=UTF-8",
		}
		resp, err := f.srv.CallJSON(ctx, &opts, &reqBody, &f.session)
		return f.shouldRetry(ctx, resp, err)
	})
	if err == nil && m != nil {
		f.opt.RefreshToken = f.session.RefreshToken
		m.Set("refresh_token", f.opt.RefreshToken)
	}
	return err
}

func (f *Fs) Mkdir(ctx context.Context, dir string) error {
	// fs.Debugf(nil, "Mkdir(\"%s\")", dir)
	_, err := f.dirCache.FindDir(ctx, dir, true)
	return err
}

// retryErrorCodes is a slice of error codes that we will retry
var retryErrorCodes = []int{
	401, // Unauthorized (seen in "Token has expired")
	500, // Get occasional 500 Internal Server Error
	502, // Bad Gateway when doing big listings
	503, // Service Unavailable
	504, // Gateway Time-out
}

// shouldRetry returns a boolean as to whether this resp and err
// deserve to be retried.  It returns the err as a convenience
func (f *Fs) shouldRetry(ctx context.Context, resp *http.Response, err error) (bool, error) {
	if fserrors.ContextError(ctx, &err) {
		return false, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		f.refreshSession(ctx, nil)
	}
	return fserrors.ShouldRetry(err) || fserrors.ShouldRetryHTTP(resp, retryErrorCodes), err
}

func (f *Fs) pdsRequestForFileItems(ctx context.Context, path string, request PDSItemsRequest) (items []BasePDSFileResponse, err error) {
	var httpResp *http.Response
	opts := rest.Opts{
		Method:       "POST",
		Path:         path,
		ContentType:  "application/json;charset=UTF-8",
		ExtraHeaders: f.session.Headers(),
	}
	var itemsResp *PDSItemsResponse
	for {
		if itemsResp != nil && itemsResp.NextMarker == "" {
			break
		}
		itemsResp = new(PDSItemsResponse)
		err = f.pacer.Call(func() (bool, error) {
			httpResp, err = f.srv.CallJSON(ctx, &opts, &request, itemsResp)
			return f.shouldRetry(ctx, httpResp, err)
		})
		if err != nil {
			return nil, errors.Wrap(err, "failed to get folder list")
		}
		items = append(items, itemsResp.Items...)
		request.SetMarker(itemsResp.NextMarker)
	}
	return
}

func (f *Fs) pdsRequestForJSON(ctx context.Context, path string, request interface{}, response interface{}) (httpResp *http.Response, err error) {
	opts := rest.Opts{
		Method:       "POST",
		Path:         path,
		ContentType:  "application/json;charset=UTF-8",
		ExtraHeaders: f.session.Headers(),
	}
	if response == nil {
		opts.NoResponse = true
	}
	err = f.pacer.Call(func() (bool, error) {
		httpResp, err = f.srv.CallJSON(ctx, &opts, request, response)
		return f.shouldRetry(ctx, httpResp, err)
	})
	return
}

func (f *Fs) pdsUpload(ctx context.Context, dirID string, name string, size int64, contentHash string, in io.Reader, options ...fs.OpenOption) (string, error) {
	var inStream io.ReadSeeker
	if data, err := ioutil.ReadAll(in); err != nil {
		return "", err
	} else {
		if size == 0 {
			size = int64(len(data))
		}
		inStream = bytes.NewReader(data)
	}

	// // try with prehash
	// preHashBytes := make([]byte, preHashBytesSize)
	// inStream.Seek(0, os.SEEK_SET)
	// if n, err := inStream.Read(preHashBytes); err != nil || n != preHashBytesSize {
	// 	return errors.Wrap(err, "failed to calculate prehash")
	// }
	// inStream.Seek(0, os.SEEK_SET)
	// preHash := fmt.Sprintf("%x", sha1.Sum(preHashBytes))
	// prehashRequest := PDSCreateFileRequest{
	// 	DriveID:       f.session.DriveID,
	// 	Name:          name,
	// 	PartInfoList:  makePartInfoList(size),
	// 	ParentFileID:  dirID,
	// 	PreHash:       preHash,
	// 	Size:          size,
	// 	Type:          FileTypeFile,
	// 	CheckNameMode: NameModeAuto,
	// }
	// httpResp, err := f.pdsRequest(ctx, apiEntryCreateFile, &prehashRequest, options...)
	// if err != nil {
	// 	return errors.Wrap(err, "failed to perform prehash check request")
	// }

	if contentHash == "" {
		var err error
		contentHash, err = CalcSHA1(size, inStream)
		if err != nil {
			return "", errors.Wrap(err, "failed to calculate content hash")
		}
	}
	proofCode, err := CalcProof(f.session.AccessToken, size, inStream)
	if err != nil {
		return "", errors.Wrap(err, "failed to calculate proof code")
	}
	response := new(PDSCreateFileResponse)
	request := PDSCreateFileRequest{
		DriveID:         f.session.DriveID,
		PartInfoList:    makePartInfoList(size),
		ParentFileID:    dirID,
		Name:            name,
		Type:            FileTypeFile,
		CheckNameMode:   NameModeAuto,
		Size:            size,
		ContentHash:     contentHash,
		ContentHashName: "sha1",
		ProofCode:       proofCode,
		ProofVersion:    "v1",
	}
	httpResp, err := f.pdsRequestForJSON(ctx, apiEntryCreateFileWithProof, &request, response)
	if err != nil {
		return "", errors.Wrap(err, "failed to post create file request")
	}
	if httpResp.StatusCode == http.StatusConflict {
		return "", errors.New("file exists")
	}
	if response.RapidUpload {
		return response.FileID, nil
	}

	// perform full upload
	inStream.Seek(0, io.SeekStart)
	for _, partInfo := range response.PartInfoList {
		partReader := io.LimitReader(inStream, uploadPartSize)
		opts := rest.Opts{
			Method:  "PUT",
			RootURL: partInfo.UploadURL,
			Body:    partReader,
		}
		httpResp, err = f.srv.Call(ctx, &opts)
		if err != nil {
			return "", errors.Wrap(err, "failed to create upload request")
		}
		httpResp.Body.Close()
	}

	// complete upload
	completeRequest := PDSCompleteFileRequest{
		DriveID:  f.session.DriveID,
		FileID:   response.FileID,
		UploadId: response.UploadId,
	}
	completeResponse := new(BasePDSFileResponse)
	_, err = f.pdsRequestForJSON(ctx, apiEntryComplete, &completeRequest, completeResponse)
	if err != nil {
		return "", errors.Wrap(err, "failed to complete upload request")
	}
	return completeResponse.FileId, nil
}

func (f *Fs) pdsList(ctx context.Context, dirID string) ([]BasePDSFileResponse, error) {
	requestData := PDSListFileRequest{
		DriveID:      f.session.DriveID,
		ParentFileID: dirID,
		Limit:        50,
	}
	return f.pdsRequestForFileItems(ctx, apiEntryListFile, &requestData)
}

func (f *Fs) pdsGetFileMeta(ctx context.Context, fileID string) (*BasePDSFileResponse, error) {
	requestData := PDSGetFileRequest{
		DriveID: f.session.DriveID,
		FileID:  fileID,
	}
	response := new(BasePDSFileResponse)
	_, err := f.pdsRequestForJSON(ctx, apiEntryGetFile, &requestData, response)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get file meta")
	}
	return response, nil
}

func (f *Fs) pdsSearch(ctx context.Context, query string) ([]BasePDSFileResponse, error) {
	requestData := PDSSearchFileRequest{
		DriveID: f.session.DriveID,
		Query:   query,
		Limit:   50,
	}
	return f.pdsRequestForFileItems(ctx, apiEntrySearchFile, &requestData)
}

func (f *Fs) pdsRemove(ctx context.Context, fileID string) error {
	requestData := PDSDeleteFileRequest{
		DriveID: f.session.DriveID,
		FileID:  fileID,
	}
	_, err := f.pdsRequestForJSON(ctx, apiEntryDeleteFile, &requestData, nil)
	return err
}

func (f *Fs) pdsCopy(ctx context.Context, srcID, dstDirID string, dstName string) (string, error) {
	requestData := PDSCopyFileRequest{
		DriveID:        f.session.DriveID,
		FileID:         srcID,
		ToParentFileID: dstDirID,
		NewName:        dstName,
		AutoRename:     true,
	}
	resp := new(PDSCopyMoveFileResponse)
	_, err := f.pdsRequestForJSON(ctx, apiEntryCopyFile, &requestData, resp)
	if err != nil {
		return "", err
	}
	return resp.FileID, nil
}

func (f *Fs) pdsMove(ctx context.Context, srcID, dstDirID string, dstName string) (string, error) {
	requestData := PDSMoveFileRequest{
		DriveID:        f.session.DriveID,
		FileID:         srcID,
		ToParentFileID: dstDirID,
		NewName:        dstName,
		Overwrite:      true,
	}
	resp := new(PDSCopyMoveFileResponse)
	_, err := f.pdsRequestForJSON(ctx, apiEntryMoveFile, &requestData, resp)
	if err != nil {
		return "", err
	}
	return resp.FileID, nil
}

func (f *Fs) pdsMkdir(ctx context.Context, dirID, name string) (*BasePDSFileResponse, error) {
	requestData := PDSCreateFileRequest{
		DriveID:       f.session.DriveID,
		CheckNameMode: NameModeRefuse,
		Name:          name,
		ParentFileID:  dirID,
		Type:          FileTypeDir,
	}
	item := new(BasePDSFileResponse)
	_, err := f.pdsRequestForJSON(ctx, apiEntryCreateFile, &requestData, item)
	if err != nil {
		return nil, err
	}
	item.Name = name
	return item, nil
}

func (f *Fs) pdsGetDownloadUrl(ctx context.Context, fileID string) (*PDSGetDownloadUrlResponse, error) {
	requestData := PDSGetDownloadUrlRequest{
		DriveID: f.session.DriveID,
		FileID:  fileID,
	}
	urlResp := new(PDSGetDownloadUrlResponse)
	_, err := f.pdsRequestForJSON(ctx, apiEntryGetFileUrl, &requestData, urlResp)
	if err != nil {
		return nil, err
	}
	return urlResp, nil
}

func (f *Fs) pdsGetFile(ctx context.Context, fileID string, options ...fs.OpenOption) (io.ReadCloser, error) {
	urlResp, err := f.pdsGetDownloadUrl(ctx, fileID)
	if err != nil {
		return nil, err
	}
	if urlResp.Url != "" {
		opts := rest.Opts{
			Method:  "GET",
			RootURL: urlResp.Url,
		}
		httpResp, err := f.srv.Call(ctx, &opts)
		if err != nil {
			return nil, err
		}
		return httpResp.Body, nil
	}
	return nil, errors.New("no download url")
}

// Rmdir deletes the root folder
//
// Returns an error if it isn't empty
func (f *Fs) Rmdir(ctx context.Context, dir string) error {
	// fs.Debugf(nil, "Rmdir(\"%s\")", path.Join(f.root, dir))
	return f.purgeCheck(ctx, dir, true)
}

// purgeCheck remotes the root directory, if check is set then it
// refuses to do so if it has anything in
func (f *Fs) purgeCheck(ctx context.Context, dir string, check bool) (err error) {
	root := path.Join(f.root, dir)
	if root == "" {
		return errors.New("can't purge root directory")
	}

	dirID, err := f.dirCache.FindDir(ctx, dir, false)
	if err != nil {
		return err
	}

	if check {
		items, err := f.pdsList(ctx, dirID)
		if err != nil {
			return err
		}
		if len(items) != 0 {
			return fs.ErrorDirectoryNotEmpty
		}
	}

	err = f.pdsRemove(ctx, dirID)
	if err != nil {
		return err
	}
	f.dirCache.FlushDir(dir)
	return
}

// Copy src to this remote using server-side copy operations.
//
// This is stored with the remote path given
//
// It returns the destination Object and a possible error
//
// Will only be called if src.Fs().Name() == f.Name()
//
// If it isn't possible then return fs.ErrorCantCopy
func (f *Fs) Copy(ctx context.Context, src fs.Object, remote string) (fs.Object, error) {
	// fs.Debugf(nil, "Copy(%v)", remote)
	srcObj, ok := src.(*Object)
	if !ok {
		fs.Debugf(src, "Can't copy - not same remote type")
		return nil, fs.ErrorCantCopy
	}
	// err := srcObj.readMetaData(ctx)
	// if err != nil {
	// 	return nil, err
	// }

	dstObj, leaf, directoryID, err := f.createObject(ctx, remote)
	if err != nil {
		fs.Debugf(src, "Failed to find dest folder")
		return nil, err
	}
	// if dest file exist and is the same file,
	// return directly
	err = dstObj.readMetaData(ctx)
	if err == nil {
		if dstObj.hash == srcObj.hash {
			return dstObj, nil
		} else {
			dstObj.Remove(ctx)
		}
	}

	dstObj.id, err = f.pdsCopy(ctx, srcObj.id, directoryID, leaf)
	if err != nil {
		return nil, err
	}

	dstObj.parentId = directoryID
	dstObj.hash = srcObj.hash
	dstObj.size = srcObj.size
	dstObj.modTime = srcObj.modTime

	return dstObj, nil
}

// Move src to this remote using server-side move operations.
//
// This is stored with the remote path given
//
// It returns the destination Object and a possible error
//
// Will only be called if src.Fs().Name() == f.Name()
//
// If it isn't possible then return fs.ErrorCantMove
func (f *Fs) Move(ctx context.Context, src fs.Object, remote string) (fs.Object, error) {
	// fs.Debugf(nil, "Move(%v)", remote)
	srcObj, ok := src.(*Object)
	if !ok {
		fs.Debugf(src, "Can't move - not same remote type")
		return nil, fs.ErrorCantCopy
	}
	// err := srcObj.readMetaData(ctx)
	// if err != nil {
	// 	return nil, err
	// }

	// Create temporary object
	dstObj, leaf, directoryID, err := f.createObject(ctx, remote)
	if err != nil {
		return nil, err
	}

	dstObj.id, err = f.pdsMove(ctx, srcObj.id, directoryID, leaf)
	if err != nil {
		return nil, err
	}

	dstObj.parentId = directoryID
	dstObj.hash = srcObj.hash
	dstObj.size = srcObj.size
	dstObj.modTime = srcObj.modTime

	return dstObj, nil
}

// DirMove moves src, srcRemote to this remote at dstRemote
// using server-side move operations.
//
// Will only be called if src.Fs().Name() == f.Name()
//
// If it isn't possible then return fs.ErrorCantDirMove
//
// If destination exists then return fs.ErrorDirExists
func (f *Fs) DirMove(ctx context.Context, src fs.Fs, srcRemote, dstRemote string) (err error) {
	srcFs, ok := src.(*Fs)
	if !ok {
		fs.Debugf(srcFs, "Can't move directory - not same remote type")
		return fs.ErrorCantDirMove
	}

	srcID, _, _, dstDirectoryID, dstLeaf, err := f.dirCache.DirMove(ctx, srcFs.dirCache, srcFs.root, srcRemote, f.root, dstRemote)
	if err != nil {
		return err
	}

	_, err = f.pdsMove(ctx, srcID, dstDirectoryID, dstLeaf)
	if err != nil {
		fs.Debugf(src, "DirMove error %v", err)
		return err
	}

	srcFs.dirCache.FlushDir(srcRemote)
	return nil
}

// Purge deletes all the files in the directory
//
// Optional interface: Only implement this if you have a way of
// deleting all the files quicker than just running Remove() on the
// result of List()
func (f *Fs) Purge(ctx context.Context, dir string) error {
	return f.purgeCheck(ctx, dir, false)
}

// Put the object into the bucket
//
// Copy the reader in to the new object which is returned
//
// The new object may have been created if an error is returned
func (f *Fs) Put(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	remote := src.Remote()

	// fs.Debugf(nil, "Put(%s)", remote)

	o, _, _, err := f.createObject(ctx, remote)
	if err != nil {
		return nil, err
	}

	return o, o.Update(ctx, in, src, options...)
}

// CreateDir makes a directory with pathID as parent and name leaf
func (f *Fs) CreateDir(ctx context.Context, pathID, leaf string) (newID string, err error) {
	// fs.Debugf(f, "CreateDir(%q, %q)\n", pathID, replaceReservedChars(leaf))
	leaf = f.opt.Enc.FromStandardName(leaf)
	item, err := f.pdsMkdir(ctx, pathID, leaf)
	if err != nil {
		return "", err
	}

	return item.FileId, nil
}

// FindLeaf finds a directory of name leaf in the folder with ID pathID
func (f *Fs) FindLeaf(ctx context.Context, pathID, leaf string) (pathIDOut string, found bool, err error) {
	// fs.Debugf(nil, "FindLeaf(\"%s\", \"%s\")", pathID, leaf)

	if pathID == "root" && leaf == "" {
		// fs.Debugf(nil, "Found Aliyundrive root")
		// that's the root directory
		return pathID, true, nil
	}

	leaf = f.opt.Enc.FromStandardName(leaf)
	query := fmt.Sprintf("parent_file_id = \"%s\" and name = \"%s\" and type = \"folder\"", pathID, leaf)
	items, err := f.pdsSearch(ctx, query)
	if err != nil {
		return "", false, err
	}
	if err == nil && len(items) == 0 {
		return "", false, nil
	}

	return items[0].FileId, true, nil
}

// Creates from the parameters passed in a half finished Object which
// must have setMetaData called on it
//
// Returns the object, leaf, directoryID and error
//
// Used to create new objects
func (f *Fs) createObject(ctx context.Context, remote string) (o *Object, leaf string, directoryID string, err error) {
	// Create the directory for the object if it doesn't exist
	leaf, directoryID, err = f.dirCache.FindPath(ctx, remote, true)
	if err != nil {
		return nil, leaf, directoryID, err
	}
	// fs.Debugf(nil, "\n...leaf %#v\n...id %#v", leaf, directoryID)
	// Temporary Object under construction
	o = &Object{
		fs:     f,
		remote: remote,
	}
	return o, f.opt.Enc.FromStandardName(leaf), directoryID, nil
}

// List the objects and directories in dir into entries.  The
// entries can be returned in any order but should be for a
// complete directory.
//
// dir should be "" to list the root, and should not have
// trailing slashes.
//
// This should return ErrDirNotFound if the directory isn't
// found.
func (f *Fs) List(ctx context.Context, dir string) (entries fs.DirEntries, err error) {
	directoryID, err := f.dirCache.FindDir(ctx, dir, false)
	if err != nil {
		return nil, err
	}

	items, err := f.pdsList(ctx, directoryID)

	for _, item := range items {
		remote := path.Join(dir, item.Name)
		mTime, err := item.GetTime()
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse node time")
		}

		if item.Type == FileTypeDir {
			d := fs.NewDir(remote, mTime)
			d.SetSize(item.Size)
			d.SetID(item.FileId)
			d.SetParentID(item.ParentFileId)
			entries = append(entries, d)
		} else {
			o := &Object{
				fs:       f,
				remote:   remote,
				id:       item.FileId,
				parentId: item.ParentFileId,
				modTime:  mTime,
				size:     item.Size,
				hash:     item.Hash,
			}
			entries = append(entries, o)
		}
	}

	return
}

// Return an Object from a path
//
// If it can't be found it returns the error fs.ErrorObjectNotFound.
func (f *Fs) newObjectWithInfo(ctx context.Context, remote string, item *BasePDSFileResponse) (fs.Object, error) {
	// fs.Debugf(nil, "newObjectWithInfo(%s, %v)", remote, item)

	var o *Object

	if item != nil {
		mTime, err := item.GetTime()
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse node time")
		}
		o = &Object{
			fs:       f,
			remote:   remote,
			id:       item.FileId,
			parentId: item.ParentFileId,
			modTime:  mTime,
			hash:     item.Hash,
			size:     item.Size,
		}

	} else {
		o = &Object{
			fs:     f,
			remote: remote,
		}

		err := o.readMetaData(ctx)
		if err != nil {
			return nil, err
		}
	}
	return o, nil
}

// NewObject finds the Object at remote.  If it can't be found
// it returns the error fs.ErrorObjectNotFound.
func (f *Fs) NewObject(ctx context.Context, remote string) (fs.Object, error) {
	// fs.Debugf(nil, "NewObject(\"%s\")", remote)
	return f.newObjectWithInfo(ctx, remote, nil)
}
