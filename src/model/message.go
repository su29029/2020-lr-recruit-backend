package model

// Message 消息报文
type Message struct {
	// 'MessageType.NEW_UPLOAD' [提交]
	// 'MessageType.NEW_FLAG_SUBMIT' [flag正确提交]
	// 'MessageType:CORRECT_ANSWER' [提交赋分]
	// 'MessageType:NEW_PROBLEM' [题目上新]
	// 'MessageType.HEART_BEAT' [心跳包]
	// 'MessageType.ERROR' [错误]
	Type    int         `json:"type"`        // 报文类型
	MsgData MessageData `json:"messageData"` // 报文主体
}

// MessageData 报文主体
type MessageData struct {
	UserID        string                 `json:"userID"`        // 发送方
	Msg           string                 `json:"msg"`           // 发送的消息内容
	ProblemStatus ProblemStatusInMessage `json:"problemStatus"` // 可选：关于题目的信息
}

// ProblemStatusInMessage 报文中的可选题目信息部分
type ProblemStatusInMessage struct {
	ProblemID       int     `json:"problemID"`
	ProblemCategory string  `json:"problemField"`
	ProblemTitle    string  `json:"problemTitle"`
	OriginScore     int     `json:"originScore"`
	Magnification   float32 `json:"magnification"`
	IsFirstBlood    bool    `json:"isFirstBlood"`
}
