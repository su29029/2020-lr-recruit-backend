package model

// Problems 结构体
type Problems struct {
	ProblemID       int    `form:"problemid" json:"problemID" binding:"-"`
	ProblemTitle    string `form:"problemtitle" json:"problemTitle" binding:"-"`
	ProblemContent  string `form:"problemcontent" json:"problemContent" binding:"-"`
	ProblemScore    int    `form:"problemscore" json:"problemScore" binding:"-"`
	CurrentScore    int    `form:"currentScore" json:"currentScore" binding:"-"`
	ProblemCategory string `form:"problemcategory" json:"problemField" binding:"-"`
	ProblemSolved   int    `form:"problemsolved" json:"problemSolved" binding:"-"`
	IsShow          bool   `form:"isshow" json:"problemIsShow" binding:"-"`
	FirstBlood      string `form:"firstblood" json:"firstBlood" binding:"-"`
	ProblemType     string `form:"problemtype" json:"problemType" binding:"-"` // value: "flag", "upload"

	Flag        string `form:"flag" json:"flag" binding:"-"`               // 某些有flag的题目需要用到
	HasSolved   bool   `form:"hassolved" json:"hasSolved" binding:"-"`     // 某个用户是否已获得该题目分数，guest端专用
	IsNewUpload int    `form:"isNewUpload" json:"isNewUpload" binding:"-"` // 某个用户上传的该题目解答是否为新上传，admin端专用
}
