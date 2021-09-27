package model

// Upload 结构体
type Upload struct {
	ProblemID   int    `json:"problemID"`
	UploadUser  string `json:"uploadUser"`
	IsNewUpload int    `json:"isNewUpload"`
}
