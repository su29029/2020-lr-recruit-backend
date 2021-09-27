package model

// ProfileItem profile键值对
type ProfileItem struct {
	Key        string      `json:"key"`
	Value      interface{} `json:"value"`
	Modifiable bool        `json:"modifiable"`
}

// Profile 用户信息
type Profile struct {
	UserID         string `json:"userID"`
	Tel            string `json:"tel"`
	Name           string `json:"name"`
	StudentID      string `json:"studentID"`
	QQNumber       string `json:"qqNumber"`
	Email          string `json:"email"`
	OldPassword    string `json:"oldPassword"`
	NewPassword    string `json:"newPassword"`
	RepeatPassword string `json:"repeatPassword"`
}
