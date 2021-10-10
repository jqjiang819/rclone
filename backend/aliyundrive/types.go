package aliyundrive

type Session struct {
	UserID       string `json:"user_id"`
	UserName     string `json:"user_name"`
	Nickname     string `json:"nick_name"`
	DomainID     string `json:"domain_id"`
	DriveID      string `json:"default_drive_id"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpireTime   string `json:"expire_time"`
}

type NameMode string
type FileType string

const (
	NameModeIgnore NameMode = "ignore"
	NameModeRefuse NameMode = "refuse"
	NameModeAuto   NameMode = "auto_rename"

	FileTypeFile FileType = "file"
	FileTypeDir  FileType = "folder"
)

type PDSItemsRequest interface {
	GetLimit() int64
	GetMarker() string
	SetLimit(int64)
	SetMarker(string)
}

type PDSItemsResponse struct {
	Items      []BasePDSFileResponse `json:"items"`
	NextMarker string                `json:"next_marker"`
}

type PDSListFileRequest struct {
	DriveID      string `json:"drive_id"`
	ParentFileID string `json:"parent_file_id"`
	Limit        int64  `json:"limit,omitempty"`
	Marker       string `json:"marker,omitempty"`
}

type BasePDSFileResponse struct {
	DownloadUrl  string   `json:"download_url,omitempty"`
	Type         FileType `json:"type"`
	Hash         string   `json:"content_hash,omitempty"`
	Name         string   `json:"name"`
	FileId       string   `json:"file_id"`
	ParentFileId string   `json:"parent_file_id,omitempty"`
	Size         int64    `json:"size,omitempty"`
	UpdatedAt    string   `json:"updated_at"`
}

type PDSSearchFileRequest struct {
	DriveID string `json:"drive_id"`
	Query   string `json:"query,omitempty"`
	Limit   int64  `json:"limit,omitempty"`
	Marker  string `json:"marker,omitempty"`
}

type PDSDeleteFileRequest struct {
	DriveID     string `json:"drive_id"`
	FileID      string `json:"file_id"`
	Permanently string `json:"permanently,omitempty"`
}

type PDSGetFileByPathRequest struct {
	DriveID  string `json:"drive_id"`
	FilePath string `json:"file_path"`
}

type PDSGetFileRequest struct {
	DriveID string `json:"drive_id"`
	FileID  string `json:"file_id"`
}

type PDSUpdateFileMetaRequest struct {
	DriveID     string `json:"drive_id"`
	FileID      string `json:"file_id"`
	Name        string `json:"name,omitempty"`
	Starred     bool   `json:"starred,omitempty"`
	Hidden      bool   `json:"hidden,omitempty"`
	Description string `json:"description,omitempty"`
}

type PDSMoveFileRequest struct {
	DriveID        string `json:"drive_id"`
	FileID         string `json:"file_id"`
	ToParentFileID string `json:"to_parent_file_id"`
	NewName        string `json:"new_name,omitempty"`
	Overwrite      bool   `json:"overwrite,omitempty"`
}

type PDSCopyFileRequest struct {
	DriveID        string `json:"drive_id"`
	FileID         string `json:"file_id"`
	ToParentFileID string `json:"to_parent_file_id"`
	ToDriveID      string `json:"to_drive_id,omitempty"`
	NewName        string `json:"new_name,omitempty"`
	AutoRename     bool   `json:"auto_rename,omitempty"`
}

type PDSCopyMoveFileResponse struct {
	DriveID string `json:"drive_id"`
	FileID  string `json:"file_id"`
}

type PDSGetDownloadUrlRequest struct {
	DriveID   string `json:"drive_id"`
	FileID    string `json:"file_id"`
	FileName  string `json:"file_name,omitempty"`
	ExpireSec int64  `json:"expire_sec,omitempty"`
}

type PDSGetDownloadUrlResponse struct {
	Size       int64             `json:"size"`
	StreamsUrl map[string]string `json:"streams_url,omitempty"`
	Url        string            `json:"url"`
}

type UploadPartInfo struct {
	Etag       string `json:"etag,omitempty"`
	PartNumber int64  `json:"part_number,omitempty"`
	PartSize   int64  `json:"part_size,omitempty"`
	UploadURL  string `json:"upload_url,omitempty"`
}

type PDSCreateFileRequest struct {
	DriveID         string           `json:"drive_id"`
	Name            string           `json:"name"`
	ParentFileID    string           `json:"parent_file_id"`
	Type            FileType         `json:"type"`
	CheckNameMode   NameMode         `json:"check_name_mode,omitempty"`
	PreHash         string           `json:"pre_hash,omitempty"`
	PartInfoList    []UploadPartInfo `json:"part_info_list,omitempty"`
	Size            int64            `json:"size,omitempty"`
	ContentHash     string           `json:"content_hash,omitempty"`
	ContentHashName string           `json:"content_hash_name,omitempty"`
	ProofCode       string           `json:"proof_code,omitempty"`
	ProofVersion    string           `json:"proof_version,omitempty"`
}

type PDSCreateFileResponse struct {
	PartInfoList []UploadPartInfo `json:"part_info_list,omitempty"`
	FileID       string           `json:"file_id"`
	RapidUpload  bool             `json:"rapid_upload"`
	UploadId     string           `json:"upload_id"`
	FileName     string           `json:"file_name"`
}

type PDSCompleteFileRequest struct {
	DriveID  string `json:"drive_id"`
	FileID   string `json:"file_id"`
	UploadId string `json:"upload_id"`
}
