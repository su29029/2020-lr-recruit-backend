package model

// UserInformation 用户信息
type UserInformation struct {
	UserID              string `json:"userID"`
	Passwd              string `json:"passwd"`
	Score               string `json:"score"`
	ProblemSolvedNumber string `json:"problemSolvedNumber"`
	Tel                 string `json:"tel"`
	Grade               int    `json:"grade"`
	StudentID           string `json:"studentID"`
	Validation          string `json:"validation"`
	Token               string `json:"token"`
}

// UserScoreStatus 用户总分情况
type UserScoreStatus struct {
	UserID        string `json:"userID"`
	HasUpload     int    `json:"hasUpload"`
	HasNewUpload  int    `json:"hasNewUpload"`
	TotalScore    int    `json:"totalScore"`
	WebScore      int    `json:"webScore"`
	UIScore       int    `json:"uiScore"`
	MLScore       int    `json:"mlScore"`
	DevScore      int    `json:"devScore"`
	SecurityScore int    `json:"securityScore"`
	BasicScore    int    `json:"basicScore"`
}
