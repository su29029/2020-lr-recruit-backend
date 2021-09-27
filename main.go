package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"time"

	"database/sql"
	"net/http"
	"strconv"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/redis"
	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/websocket"

	"lrstudio.com/model"
	"lrstudio.com/utils"
	"lrstudio.com/way"
)

func main() {
	r := router()
	r.Run(":8080")
}

func router() *gin.Engine {
	r := gin.Default()
	go way.DealWithBlankProblem()
	store, _ := redis.NewStore(1000, "tcp", "redis:6379", "", []byte("secret"))
	r.Use(sessions.Sessions("sessionid", store))
	r.Use(way.LoginIntercepter())

	r.POST("/api/guest/login", loginHandler)
	r.GET("/api/guest/islogin", checkLoginHandler)
	r.POST("/api/guest/logout", logoutHandler)
	r.POST("/api/guest/register", guestRegisterHandler)

	r.POST("/api/guest/validation", guestGetValidationHandler)
	r.POST("/api/guest/checkvalidation", guestCheckValidationHandler) // 考虑优化注册接口

	r.GET("/api/guest/getProblem/:field", guestGetProblemHandler)
	r.GET("/api/guest/problemDetail/:id", guestGetProblemDetailHandler)

	r.GET("/api/guest/profile/userinformation/:userID", guestGetProfileInformationHandler)
	r.GET("/api/guest/profile/solves/:userID", guestGetProfileSolvesHandler)
	r.POST("/api/guest/profile/savechanges", guestSaveProfileChangesHandler)
	r.GET("/api/guest/allprofile/:userID", guestGetAllProfileHandler)

	r.GET("/api/guest/rank/:field", guestGetRankHandler)

	r.POST("/api/guest/submit/checkflag", guestCheckFlagHandler)
	r.POST("/api/guest/upload", guestUploadHandler)
	r.GET("/api/guest/getuploads/:field/:userID", guestGetUploadsHandler)

	r.POST("/api/admin/login", loginHandler)
	r.GET("/api/admin/islogin", checkLoginHandler)
	r.POST("/api/admin/logout", logoutHandler)

	r.GET("/api/admin/detail/:field", adminGetFieldDetailHandler)
	r.GET("/api/admin/problem/getproblem/:field", adminGetProblemHandler)

	r.POST("/api/admin/users/updatescore", adminUpdateUserScoreHandler)
	r.POST("/api/admin/users/deleteuser", adminDeleteUserHandler) // unfinished
	r.GET("/api/admin/problem/getproblemupload/:problemID", adminGetProblemUploadHandler)
	r.POST("/api/admin/problem/savechanges", adminSaveProblemChangesHandler)
	r.POST("/api/admin/problem/deleteproblem", adminDeleteProblemHandler)
	r.POST("/api/admin/problem/sort", adminSortProblemHandler)

	r.GET("/api/admin/problem/newproblem/:field", adminNewProblemHandler)
	r.GET("/api/admin/users/getallusers", adminGetAllUsersHandler)
	r.GET("/api/admin/users/getallprofile/:userID", adminGetUserProfileHandler)
	r.GET("/api/admin/users/getalluploads/:userID", adminGetUserUploadsHandler)
	r.GET("/api/admin/users/download/:userID/:problemID", adminDownloadUserUploadHandler)
	r.GET("/api/admin/users/getusersubmits/:userID", adminGetUserSubmitsHandler)

	r.GET("/api/ws/connect/:userID", newConnectionHandler)
	return r
}

func newConnectionHandler(c *gin.Context) {
	userID := c.Param("userID")
	upGrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}
	ws, err := upGrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"msg": "error",
		})
		return
	}
	client := way.NewClient(ws.RemoteAddr().String(), userID, ws)
	if client != nil {
		fmt.Println("A new connection,userID is", userID, ", ip address is", ws.RemoteAddr().String())
		go client.Read()
		go client.Write()
		model.Manager.Connect <- client
	} else {
		// ws.Close()
		msg := model.Message{
			Type: utils.MessageType["ERROR"],
			MsgData: model.MessageData{
				Msg: "repeated_connect",
			},
		}
		ws.WriteJSON(&msg)
		ws.Close()
	}
}

func loginHandler(c *gin.Context) {
	var user model.UserInformation
	var err error
	err = c.BindJSON(&user)
	user.Passwd = way.Md5(user.Passwd)
	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "error",
		})
		return
	}
	var captcha struct {
		Secret   string
		Response string
		Remoteip string
	}
	var verifyResponse struct {
		Success     bool   `json:"success"`
		ChallengeTs string `json:"challenge_ts"`
		Hostname    string `json:"hostname"`
		ErrorCodes  int    `json:"error-codes"`
	}
	captcha.Secret = "6LchkscZAAAAANS1mcA9Zb39HvOBgXD-XloOELtT"
	captcha.Response = user.Token
	captcha.Remoteip = c.ClientIP()

	captchaVerify, err := http.Post("https://www.recaptcha.net/recaptcha/api/siteverify", "application/x-www-form-urlencoded", strings.NewReader("secret="+captcha.Secret+"&response="+captcha.Response))
	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"msg": "error",
		})
		return
	}
	content, _ := ioutil.ReadAll(captchaVerify.Body)
	err = json.Unmarshal(content, &verifyResponse)
	if !verifyResponse.Success {
		c.JSON(http.StatusOK, gin.H{
			"msg": "auth_error",
		})
		return
	}

	if c.Request.URL.Path == "/api/admin/login" {
		if way.Md5(user.UserID) == "a0e6ff00131e8f13fe9d4e65044a8b1a" && user.Passwd == "29d1f33f372bcdc9ed5c0a29554d975f" {
			way.SetSession(c, "user", user.UserID, 3600*3)
			c.Header("Access-Control-Allow-Credentials", "true")
			c.JSON(http.StatusOK, gin.H{
				"msg": "succeed_login",
			})
		} else {
			c.JSON(http.StatusOK, gin.H{
				"msg": "fail_login",
			})
		}
		return
	}

	err = utils.Db.QueryRow("select userID from user_table where userID = ? and passwd = ?", user.UserID, user.Passwd).Scan(&user.UserID)
	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusOK, gin.H{
			"msg": "fail_login",
		})
	} else {
		way.SetSession(c, "user", user.UserID, 3600*3)
		c.Header("Access-Control-Allow-Credentials", "true")
		c.JSON(http.StatusOK, gin.H{
			"msg": "succeed_login",
		})
	}
}

func checkLoginHandler(c *gin.Context) {
	user := way.GetSession(c, "user")
	if user == "" {
		c.JSON(http.StatusOK, gin.H{
			"msg": "intercept",
		})
	} else {
		way.SetSession(c, "user", user, 3600*3)
		c.JSON(http.StatusOK, gin.H{
			"msg":  "pass",
			"user": user,
		})
	}
}

func logoutHandler(c *gin.Context) {
	var user model.UserInformation
	session := sessions.Default(c)
	c.ShouldBind(&user)
	if user.UserID != way.GetSession(c, "user") {
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "error",
		})
		return
	}
	session.Delete("user")
	session.Save()
	c.JSON(http.StatusOK, gin.H{
		"msg": "success",
	})
}

// 接收手机号并发送验证码
func guestGetValidationHandler(c *gin.Context) {
	var user model.UserInformation
	c.ShouldBind(&user)
	code := way.Code()
	fmt.Println(code)

	sendRes := way.SendMsg(user.Tel, code)
	if sendRes == "failed" {
		c.JSON(http.StatusInternalServerError, gin.H{
			"msg": "error",
		})
	} else {
		if !way.SetRedisPair(user.Tel, code, 300) {
			c.JSON(http.StatusInternalServerError, gin.H{
				"msg": "error",
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"msg": sendRes,
		})
	}
}

func guestCheckValidationHandler(c *gin.Context) {
	var checkPair struct {
		Tel        string `json:"tel"`
		Validation string `json:"validation"`
	}
	c.ShouldBind(&checkPair)
	if way.Validation(checkPair.Validation, checkPair.Tel) == 0 {
		c.JSON(http.StatusOK, gin.H{
			"msg": "auth_error",
		})
	} else {
		c.JSON(http.StatusOK, gin.H{
			"msg": "success",
		})
	}
}

func guestRegisterHandler(c *gin.Context) {
	var user model.UserInformation
	err := c.BindJSON(&user)
	user.Passwd = way.Md5(user.Passwd)
	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "error",
		})
		return
	}
	if !way.CheckInformation(user) {
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "information_invalid",
		})
		return
	}
	if way.Validation(user.Validation, user.Tel) == 0 {
		c.JSON(http.StatusOK, gin.H{
			"msg": "wrong_code",
		})
		return
	}

	// 注册数据
	// 检查手机号，用户名，学号分别是否有被注册
	var checkIsRegister string
	err = utils.Db.QueryRow("SELECT userID FROM user_table where userID = ?", user.UserID).Scan(&checkIsRegister)
	if err == nil {
		fmt.Println(">>> username_is_registered <<<")
		c.JSON(http.StatusOK, gin.H{
			"msg": "username_is_registered",
		})
		return
	}

	err = utils.Db.QueryRow("SELECT student_id FROM user_table where student_id = ?", user.StudentID).Scan(&checkIsRegister)
	if err == nil {
		fmt.Println(">>> stu_number_is_registered <<<")
		c.JSON(http.StatusOK, gin.H{
			"msg": "stu_number_is_registered",
		})
		return
	}

	err = utils.Db.QueryRow("SELECT tel FROM user_table where tel = ?", user.Tel).Scan(&checkIsRegister)
	if err == nil {
		fmt.Println(">>> phone_number_is_registered <<<")
		c.JSON(http.StatusOK, gin.H{
			"msg": "phone_number_is_registered",
		})
		return
	}

	_, err = utils.Db.Exec("INSERT INTO user_table(userID, passwd, tel, student_id, score, problem_solved_number, grade, has_upload, has_new_upload)VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)", user.UserID, user.Passwd, user.Tel, user.StudentID, 0, 0, user.Grade, 0, 0)
	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusOK, gin.H{
			"msg": "fail_register",
		})
	} else {
		c.JSON(http.StatusOK, gin.H{
			"msg": "succeed_register",
		})
	}
}

func guestGetRankHandler(c *gin.Context) {
	var res []model.Rank
	var rank model.Rank
	var err error
	var field int
	field, err = strconv.Atoi(c.Param("field"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "error",
		})
		return
	}

	if field == 6 {
		rows, err := utils.Db.Query("select * from (select @rank := @rank + 1 as rank, userID, score, problem_solved_number from user_table p, (select @rank := 0) q order by score desc) m")
		if err != nil {
			fmt.Println(err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"msg": "error",
			})
			return
		}
		for rows.Next() {
			rows.Scan(&rank.Rank, &rank.UserID, &rank.SolvedProblemScore, &rank.SolvedProblemNumber)
			res = append(res, rank)
		}
		c.JSON(http.StatusOK, res)
	} else {
		rows, err := utils.Db.Query("select userID, round(sum(solved_problem_score * magnification)) as 'score', count(distinct solved_problem_id) as 'solves' from problem_solved_table where solved_problem_field = ? group by userID order by score desc", field)
		if err != nil {
			fmt.Println(err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"msg": "error",
			})
			return
		}
		for rows.Next() {
			rows.Scan(&rank.UserID, &rank.SolvedProblemScore, &rank.SolvedProblemNumber)
			res = append(res, rank)
		}
		c.JSON(http.StatusOK, res)
	}

}

func guestGetProfileInformationHandler(c *gin.Context) {
	var userID string
	var score, solves, rank int
	var err error

	userID = c.Param("userID")

	err = utils.Db.QueryRow("SELECT score, problem_solved_number FROM user_table WHERE userID = ?", userID).Scan(&score, &solves)

	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"msg": "error",
		})
		return
	}
	err = utils.Db.QueryRow("select rank from (select userID, @rank := @rank + 1 as rank from user_table p, (select @rank := 0) q order by score desc) m where userID = ?", userID).Scan(&rank)

	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"msg": "error",
		})
		return
	}
	var solvesNumber struct {
		Web      int `json:"web"`
		UI       int `json:"ui"`
		ML       int `json:"ml"`
		Dev      int `json:"dev"`
		Security int `json:"security"`
		Basic    int `json:"basic"`
	}

	err = utils.Db.QueryRow("select @userID := ? as 'web','ui','ml','dev','security','basic' union select (select count(distinct solved_problem_id) from problem_solved_table where userID = @userID and solved_problem_field = 0 ),(select count(distinct solved_problem_id) from problem_solved_table where userID = @userID and solved_problem_field = 1 ),(select count(distinct solved_problem_id) from problem_solved_table where userID = @userID and solved_problem_field = 2 ),(select count(distinct solved_problem_id) from problem_solved_table where userID = @userID and solved_problem_field = 3 ),(select count(distinct solved_problem_id) from problem_solved_table where userID = @userID and solved_problem_field = 4 ),(select count(distinct solved_problem_id) from problem_solved_table where userID = @userID and solved_problem_field = 5 ) limit 1,1;", userID).Scan(&solvesNumber.Web, &solvesNumber.UI, &solvesNumber.ML, &solvesNumber.Dev, &solvesNumber.Security, &solvesNumber.Basic)

	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"msg": "error",
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"userID":      userID,
		"score":       score,
		"totalSolves": solves,
		"rank":        rank,
		"web":         solvesNumber.Web,
		"ui":          solvesNumber.UI,
		"ml":          solvesNumber.ML,
		"dev":         solvesNumber.Dev,
		"security":    solvesNumber.Security,
		"basic":       solvesNumber.Basic,
	})
}

func guestGetAllProfileHandler(c *gin.Context) {
	var userID string
	var profileItem model.ProfileItem
	var profile []model.ProfileItem
	var err error
	var keys []string = []string{"userID", "tel", "name", "studentID", "QQnumber", "email"}
	var values []interface{} = make([]interface{}, len(keys))
	var sqlStr string

	userID = c.Param("userID")
	sqlStr = "select userID, tel, name, student_id, qq_number, email from user_table where userID = ?" // 最好改成动态的
	err = utils.Db.QueryRow(sqlStr, userID).Scan(&values[0], &values[1], &values[2], &values[3], &values[4], &values[5])
	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"msg": "error",
		})
		return
	}
	for i := 0; i < len(keys); i++ {
		profileItem.Key = keys[i]
		profileItem.Value = values[i]
		if keys[i] == "userID" {
			profileItem.Modifiable = false
		} else {
			profileItem.Modifiable = true
		}
		profile = append(profile, profileItem)
	}
	c.JSON(http.StatusOK, profile)
}

func guestSaveProfileChangesHandler(c *gin.Context) {
	// var profile model.Profile
	var profile struct {
		PrevProfile    model.Profile `json:"prevProfile"`
		CurrentProfile model.Profile `json:"currentProfile"`
	}

	var sqlStr string
	var err error
	var oldPassword string
	c.ShouldBind(&profile)
	// 0.检查数据合法性
	if !way.CheckInformation(profile.CurrentProfile) {
		c.JSON(http.StatusOK, gin.H{
			"msg": "information_invalid",
		})
		return
	}
	sqlStr = "select passwd from user_table where userID = ? "
	err = utils.Db.QueryRow(sqlStr, profile.PrevProfile.UserID).Scan(&oldPassword)
	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"msg": "error",
		})
		return
	}
	if oldPassword != way.Md5(profile.CurrentProfile.OldPassword) {
		c.JSON(http.StatusOK, gin.H{
			"msg": "old_password_invalid",
		})
		return
	}
	if profile.CurrentProfile.NewPassword != "" {
		profile.CurrentProfile.NewPassword = way.Md5(profile.CurrentProfile.NewPassword)
	} else {
		profile.CurrentProfile.NewPassword = way.Md5(profile.CurrentProfile.OldPassword)
	}
	sqlStr = "update user_table set passwd = ?, student_id = ?, tel = ?, qq_number = ?, name = ?, email = ? where userID = ?"
	_, err = utils.Db.Exec(sqlStr,
		profile.CurrentProfile.NewPassword,
		profile.CurrentProfile.StudentID,
		profile.CurrentProfile.Tel,
		profile.CurrentProfile.QQNumber,
		profile.CurrentProfile.Name,
		profile.CurrentProfile.Email,
		profile.PrevProfile.UserID)
	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"msg": "error",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"msg": "success",
	})
}

func guestGetProfileSolvesHandler(c *gin.Context) {
	var userID string
	var solved model.UserSolved
	var res []model.UserSolved
	var rows *sql.Rows
	var err error
	var field []string = []string{"web", "UI", "机器学习", "DevOps", "网络安全", "基础"}
	//获取登录用户
	userID = c.Param("userID")

	rows, err = utils.Db.Query("SELECT solved_problem_id, solved_problem_title, solved_problem_field, solved_problem_score, magnification, solved_problem_time FROM problem_solved_table WHERE userID = ?", userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"msg": "error",
		})
	}
	for rows.Next() {
		rows.Scan(&solved.ProblemID, &solved.ProblemTitle, &solved.ProblemCategory, &solved.ProblemScore, &solved.Magnification, &solved.SolvedTime)
		fieldTag, _ := strconv.Atoi(solved.ProblemCategory)
		solved.ProblemCategory = field[fieldTag]
		res = append(res, solved)
	}
	c.JSON(http.StatusOK, res)
}

func guestGetProblemHandler(c *gin.Context) {
	field, err := strconv.Atoi(c.Param("field"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "error",
		})
		return
	}
	session := sessions.Default(c)
	userID := session.Get("user")
	if userID == nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"msg": "session expired",
		})
		return
	}
	if way.Unsafe(userID.(string)) {
		c.JSON(http.StatusBadRequest, nil)
		return
	}

	problems, _ := way.GuestGetProblemsByField(field, userID.(string))

	c.JSON(http.StatusOK, problems)
}

func guestGetProblemDetailHandler(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "error",
		})
	}
	problem, _ := way.GuestGetProblemDetailByID(id)

	c.JSON(http.StatusOK, problem)
}

func adminGetFieldDetailHandler(c *gin.Context) {
	field, err := strconv.Atoi(c.Param("field"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "error",
		})
	}
	fmt.Println(field)

	overview, _ := way.AdminGetFieldOverview(field)

	detail, _ := way.AdminGetFieldDetail(field)

	c.JSON(http.StatusOK, gin.H{
		"overview": overview,
		"detail":   detail,
	})
}

func adminGetProblemHandler(c *gin.Context) {
	field, err := strconv.Atoi(c.Param("field"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "error",
		})
	}

	problems, _ := way.AdminGetProblemsByField(field)

	c.JSON(http.StatusOK, problems)
}

func adminGetUserSubmitsHandler(c *gin.Context) {
	var submits []model.UserSolved
	var submit model.UserSolved
	userID := c.Param("userID")
	query := "select userID, solved_problem_id, solved_problem_score, magnification from problem_solved_table where userID = ?"
	rows, err := utils.Db.Query(query, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"msg": "error",
		})
		return
	}
	for rows.Next() {
		rows.Scan(&submit.UserID, &submit.ProblemID, &submit.ProblemScore, &submit.Magnification)
		submits = append(submits, submit)
	}
	c.JSON(http.StatusOK, submits)
}

func adminGetUserUploadsHandler(c *gin.Context) {
	var problems []model.Problems
	var problem model.Problems
	var problemIDs []int
	var isNewUpload map[int]int
	var rows *sql.Rows
	var err error

	userID := c.Param("userID")
	dst := path.Join("/app/upload", userID)
	if res, _ := way.IsFileExist(dst); !res {
		c.JSON(http.StatusOK, problems)
		return
	}
	file, err := ioutil.ReadDir(dst)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"msg": "error",
		})
		return
	}

	isNewUpload = make(map[int]int)
	for _, f := range file {
		if !f.IsDir() {
			flag := 0 // 是否新上传
			fileName := f.Name()
			if fileName[0:3] == "new" {
				fileName = fileName[4:]
				flag = 1
			}
			index := strings.Index(fileName, "_")
			if index < 0 {
				c.JSON(http.StatusInternalServerError, gin.H{
					"msg": "error",
				})
				return
			}
			problemID, err := strconv.Atoi(fileName[:index])
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"msg": "error",
				})
				return
			}
			if flag == 1 {
				isNewUpload[problemID] = 1
			} else {
				isNewUpload[problemID] = 0
			}
			problemIDs = append(problemIDs, problemID)
		}
	}

	// 通过数据库查找出problemIDs对应的题目的题目名等信息

	query := fmt.Sprintf("select problem_id, problem_title, problem_category, problem_score, current_score, problem_solved from problem_table where problem_id in (%s)", way.PlaceHolders(len(problemIDs)))

	rows, err = utils.Db.Query(query, way.TransferToInterface(problemIDs)...)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"msg": "error",
		})
		return
	}
	for rows.Next() {
		rows.Scan(&problem.ProblemID, &problem.ProblemTitle, &problem.ProblemCategory, &problem.ProblemScore, &problem.CurrentScore, &problem.ProblemSolved)
		problem.IsNewUpload = isNewUpload[problem.ProblemID]
		problems = append(problems, problem)
	}
	c.JSON(http.StatusOK, problems)
}

func adminGetUserProfileHandler(c *gin.Context) {
	var userID string
	var profileItem model.ProfileItem
	var profile []model.ProfileItem
	var err error
	var keys []string = []string{"userID", "passwd", "tel", "name", "studentID", "QQnumber", "email", "problemSolvedNumber"}
	var values []interface{} = make([]interface{}, len(keys))
	var sqlStr string

	userID = c.Param("userID")
	sqlStr = "select userID, passwd, tel, name, student_id, qq_number, email, problem_solved_number from user_table where userID = ?" // 最好改成动态的
	err = utils.Db.QueryRow(sqlStr, userID).Scan(&values[0], &values[1], &values[2], &values[3], &values[4], &values[5], &values[6], &values[7])
	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"msg": "error",
		})
		return
	}
	for i := 0; i < len(keys); i++ {
		profileItem.Key = keys[i]
		profileItem.Value = values[i]
		profileItem.Modifiable = true
		profile = append(profile, profileItem)
	}
	c.JSON(http.StatusOK, profile)
}

func adminDownloadUserUploadHandler(c *gin.Context) {
	userID := c.Param("userID")
	problemID, err := strconv.Atoi(c.Param("problemID"))

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "error",
		})
	}
	dst := path.Join("/app/upload", userID)

	if res, _ := way.IsFileExist(dst); !res {
		c.JSON(http.StatusNotFound, gin.H{
			"msg": "error",
		})
		return
	}

	file, err := ioutil.ReadDir(dst)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"msg": "error",
		})
		return
	}

	flag := 0
	for _, f := range file {
		if !f.IsDir() {
			id := 0
			fileName := f.Name()
			if fileName[0:3] == "new" {
				fileName = fileName[4:] // 如果为新上传，则暂时删除掉文件名前面的new
				flag++
			}
			index := strings.Index(fileName, "_")
			if index > 0 {
				id, _ = strconv.Atoi(fileName[:index])
			} else {
				c.JSON(http.StatusInternalServerError, gin.H{
					"msg": "error",
				})
				return
			}
			if id == problemID { // 找到了需要下载的文件
				if f.Name()[0:3] == "new" {
					os.Rename(path.Join("/app/upload", userID, f.Name()), path.Join("/app/upload", userID, f.Name()[4:]))
				}
				c.Writer.Header().Add("Content-Disposition", fmt.Sprintf("attachment; fileName=%s", way.Base64Encode(fileName)))
				suffix := path.Ext(fileName)
				switch suffix {
				case ".zip":
					c.Writer.Header().Add("Content-Type", "application/zip")
				case ".rar":
					c.Writer.Header().Add("Content-Type", "application/x-rar-compressed")
				case ".pdf":
					c.Writer.Header().Add("Content-Type", "application/pdf")
				case ".doc":
					c.Writer.Header().Add("Content-Type", "application/msword")
				case ".docx":
					c.Writer.Header().Add("Content-Type", "application/vnd.openxmlformats-officedocument.wordprocessing")
				case ".md":
					c.Writer.Header().Add("Content-Type", "text/markdown")
				default:
					if strings.Index(fileName, ".tar.gz") > -1 {
						c.Writer.Header().Add("Content-Type", "application/gzip")
					} else {
						c.Writer.Header().Add("Content-Type", "application/octet-stream")
					}
				}
				flag--
				c.Writer.Header().Add("filename", way.Base64Encode(fileName))
				c.File(path.Join(dst, fileName))
			}
		}
	}
	if flag == 0 { // 下载完了之后发现没有新的文件了
		_, err := utils.Db.Exec("update user_table set has_new_upload = 0 where userID = ?", userID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"msg": "error",
			})
			return
		}
	}
}

func adminUpdateUserScoreHandler(c *gin.Context) {
	var userSolved model.UserSolved
	var user model.UserScoreStatus
	var problem model.Problems
	var currentTime string
	var sqlStr string
	var row *sql.Row
	var err error

	var ifSolvedProblemExist int = 0
	var magnification float32 = 0
	c.ShouldBind(&userSolved)
	fmt.Println(userSolved)
	if userSolved.UserID == "" || userSolved.ProblemID == 0 || userSolved.Magnification < 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "error",
		})
		return
	}

	// 0.获取系统时间，通过 problemID 获取题目信息
	currentTime = time.Now().String()
	currentTime = currentTime[:strings.Index(currentTime, ".")]
	sqlStr = "select problem_id, problem_title, problem_category, problem_score, current_score, problem_solved from problem_table where problem_id = ?"
	row = utils.Db.QueryRow(sqlStr, userSolved.ProblemID)
	row.Scan(&problem.ProblemID, &problem.ProblemTitle, &problem.ProblemCategory, &problem.ProblemScore, &problem.CurrentScore, &problem.ProblemSolved)
	if userSolved.ProblemCategory != problem.ProblemCategory {
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "error",
		})
		return
	}
	// 1.向 problem_solved_table 中插入一条记录
	sqlStr = "select count(solved_problem_id) from problem_solved_table where solved_problem_id = ? and userID = ?"
	row = utils.Db.QueryRow(sqlStr, userSolved.ProblemID, userSolved.UserID)
	row.Scan(&ifSolvedProblemExist)
	sqlStr = "select magnification from problem_solved_table where solved_problem_id = ? and userID = ?"
	row = utils.Db.QueryRow(sqlStr, userSolved.ProblemID, userSolved.UserID)
	row.Scan(&magnification)
	if ifSolvedProblemExist > 0 {
		sqlStr = "update problem_solved_table set magnification = ?, solved_problem_time = ? where solved_problem_id = ? and userID = ?"
		_, err = utils.Db.Exec(sqlStr, userSolved.Magnification, currentTime, userSolved.ProblemID, userSolved.UserID)
		if err != nil {
			fmt.Println(err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"msg": "error",
			})
			return
		}
	} else {
		sqlStr = "insert into problem_solved_table (userID, solved_problem_id, solved_problem_title, solved_problem_field, solved_problem_score, magnification, solved_problem_time) values (?, ?, ?, ?, ?, ?, ?)"
		_, err = utils.Db.Exec(sqlStr, userSolved.UserID, problem.ProblemID, problem.ProblemTitle, problem.ProblemCategory, problem.CurrentScore, userSolved.Magnification, currentTime)
		if err != nil {
			fmt.Println(err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"msg": "error",
			})
			return
		}
	}

	// 2.更新 problem_table 中题目的数据，并修改题目当前分值
	currentScore := way.CalculateCurrentScore(problem.ProblemScore, problem.ProblemSolved+(ifSolvedProblemExist^1), 30)
	sqlStr = "update problem_table set problem_solved = problem_solved + 1 - ?, current_score = ? where problem_id = ?"
	_, err = utils.Db.Exec(sqlStr, ifSolvedProblemExist, currentScore, userSolved.ProblemID)
	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"msg": "error",
		})
		return
	}

	sqlStr = "update problem_solved_table set solved_problem_score = ? where solved_problem_id = ?" // 题目的最终得分是动态计算的
	_, err = utils.Db.Exec(sqlStr, currentScore, userSolved.ProblemID)
	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"msg": "error",
		})
		return
	}
	// 3. 如果是一血，设置一血
	sqlStr = "update problem_table set first_blood = ? where problem_id = ? and first_blood = ''"
	res, err := utils.Db.Exec(sqlStr, userSolved.UserID, userSolved.ProblemID)
	rowsAffected, _ := res.RowsAffected()
	fmt.Println("firstblood ", rowsAffected)
	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"msg": "error",
		})
		return
	}

	// 4. 更新 user_table 表中解出题目的数据
	sqlStr = "update user_table set problem_solved_number = problem_solved_number + 1 - ? where userID = ?"
	_, err = utils.Db.Exec(sqlStr, ifSolvedProblemExist, userSolved.UserID)
	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"msg": "error",
		})
		return
	}

	// 5. 返回数据
	sqlStr = "select userID, round(sum(solved_problem_score * magnification)) as 'totalScore' from problem_solved_table where userID = ? group by userID"
	row = utils.Db.QueryRow(sqlStr, userSolved.UserID)
	row.Scan(&user.UserID, &user.TotalScore)

	sqlStr = "select round(sum(solved_problem_score * magnification)) as 'webScore' from problem_solved_table where solved_problem_field = 0 and userID = ? group by userID"
	row = utils.Db.QueryRow(sqlStr, userSolved.UserID)
	row.Scan(&user.WebScore)

	sqlStr = "select round(sum(solved_problem_score * magnification)) as 'uiScore' from problem_solved_table where solved_problem_field = 1 and userID = ? group by userID"
	row = utils.Db.QueryRow(sqlStr, userSolved.UserID)
	row.Scan(&user.UIScore)

	sqlStr = "select round(sum(solved_problem_score * magnification)) as 'mlScore' from problem_solved_table where solved_problem_field = 2 and userID = ? group by userID"
	row = utils.Db.QueryRow(sqlStr, userSolved.UserID)
	row.Scan(&user.MLScore)

	sqlStr = "select round(sum(solved_problem_score * magnification)) as 'devScore' from problem_solved_table where solved_problem_field = 3 and userID = ? group by userID"
	row = utils.Db.QueryRow(sqlStr, userSolved.UserID)
	row.Scan(&user.DevScore)

	sqlStr = "select round(sum(solved_problem_score * magnification)) as 'securityScore' from problem_solved_table where solved_problem_field = 4 and userID = ? group by userID"
	row = utils.Db.QueryRow(sqlStr, userSolved.UserID)
	row.Scan(&user.SecurityScore)

	sqlStr = "select round(sum(solved_problem_score * magnification)) as 'basicScore' from problem_solved_table where solved_problem_field = 5 and userID = ? group by userID"
	row = utils.Db.QueryRow(sqlStr, userSolved.UserID)
	row.Scan(&user.BasicScore)

	// 6. 广播CORRECT_ANSWER消息
	var msg model.Message
	msg.Type = utils.MessageType["CORRECT_ANSWER"]
	msg.MsgData = model.MessageData{
		UserID: userSolved.UserID,
		Msg:    "correct_answer",
		ProblemStatus: model.ProblemStatusInMessage{
			ProblemID:       userSolved.ProblemID,
			ProblemCategory: problem.ProblemCategory,
			ProblemTitle:    problem.ProblemTitle,
			OriginScore:     currentScore,
			Magnification:   magnification,
			IsFirstBlood:    rowsAffected > 0,
		},
	}
	model.Manager.Broadcast <- msg
	c.JSON(http.StatusOK, user)
}

func adminDeleteUserHandler(c *gin.Context) {

}

func adminNewProblemHandler(c *gin.Context) {
	var problem model.Problems

	field, err := strconv.Atoi(c.Param("field"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "error",
		})
	}

	sqlStr := "insert into problem_table (problem_title, problem_content, problem_score, current_score, problem_category, problem_solved, flag, is_show, first_blood, sort_id) values ('', '', 0, 0, ?, 0, '', 0, '', 0)"
	res, err := utils.Db.Exec(sqlStr, field)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"msg": "error",
		})
		return
	}

	id, err := res.LastInsertId()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"msg": "error",
		})
		return
	}
	problem.ProblemID = int(id)
	c.JSON(http.StatusOK, problem)
}

func adminSaveProblemChangesHandler(c *gin.Context) {
	var problem model.Problems
	var sqlStr string
	var row *sql.Row
	var num int
	var solves int = 0
	var err error
	c.ShouldBind(&problem)

	fmt.Println(problem)
	sqlStr = "select count(problem_id) from problem_table where problem_id = ?"
	row = utils.Db.QueryRow(sqlStr, problem.ProblemID)
	row.Scan(&num)
	sqlStr = "select problem_solved from problem_table where problem_id = ?"
	row = utils.Db.QueryRow(sqlStr, problem.ProblemID)
	row.Scan(&solves)
	if num > 0 {
		sqlStr = "update problem_table set problem_title = ?, problem_content = ?, problem_score = ?, current_score = ?, flag = ?, is_show = ? where problem_id = ?"
		var currentScore int = 0
		currentScore = way.CalculateCurrentScore(problem.ProblemScore, solves, 30)
		_, err = utils.Db.Exec(sqlStr, problem.ProblemTitle, problem.ProblemContent, problem.ProblemScore, currentScore, problem.Flag, problem.IsShow, problem.ProblemID)
		if err != nil {
			fmt.Println(err)
			c.JSON(http.StatusInternalServerError, err)
		}
		sqlStr = "update problem_solved_table set solved_problem_title = ?, solved_problem_score = ? where solved_problem_id = ?"
		_, err = utils.Db.Exec(sqlStr, problem.ProblemTitle, currentScore, problem.ProblemID)
		if err != nil {
			fmt.Println(err)
			c.JSON(http.StatusInternalServerError, err)
		}
		c.JSON(http.StatusOK, gin.H{
			"msg": "success",
		})
	} else {
		c.JSON(http.StatusForbidden, gin.H{
			"msg": "error",
		})
	}

}

func adminSortProblemHandler(c *gin.Context) {
	var problems []model.Problems
	c.ShouldBind(&problems)
	for index, problem := range problems {
		sqlStr := "update problem_table set sort_id = ? where problem_id = ?"
		_, err := utils.Db.Exec(sqlStr, index, problem.ProblemID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, err)
			return
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"status": "success",
	})
}

func adminDeleteProblemHandler(c *gin.Context) {
	var problem model.Problems
	var rows *sql.Rows
	var affectedUsers []struct {
		affectedUserID string
		affectedScore  int
	}
	var affectedUser struct {
		affectedUserID string
		affectedScore  int
	}
	var sqlStr string
	var err error
	c.BindJSON(&problem)

	sqlStr = "delete from problem_table where problem_id = ?"

	_, err = utils.Db.Exec(sqlStr, problem.ProblemID)

	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusInternalServerError, err)
	}
	sqlStr = "select userID, (solved_problem_score * magnification) from problem_solved_table where solved_problem_id = ?"
	rows, err = utils.Db.Query(sqlStr, problem.ProblemID)
	if err == nil {
		for rows.Next() {
			rows.Scan(&affectedUser.affectedUserID, &affectedUser.affectedScore)
			affectedUsers = append(affectedUsers, affectedUser)
		}
	}
	for i := 0; i < len(affectedUsers); i++ { // low efficiency
		sqlStr = "update user_table set problem_solved_number = problem_solved_number - 1, score = score - ? where userID = ?"
		_, err = utils.Db.Exec(sqlStr, affectedUsers[i].affectedScore, affectedUsers[i].affectedUserID)
		if err != nil {
			fmt.Println(err)
			c.JSON(http.StatusInternalServerError, err)
		}
	}

	sqlStr = "delete from problem_solved_table where solved_problem_id = ?"
	_, err = utils.Db.Exec(sqlStr, problem.ProblemID)

	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusInternalServerError, err)
	}

	c.JSON(http.StatusOK, gin.H{
		"msg": "success",
	})
}

func adminGetAllUsersHandler(c *gin.Context) {
	var users []model.UserScoreStatus
	var user model.UserScoreStatus

	var sqlStr string
	var rows *sql.Rows
	var err error
	var i int

	sqlStr = "select userID, has_upload, has_new_upload from user_table order by userID"

	rows, err = utils.Db.Query(sqlStr)
	if err == nil {
		for rows.Next() {
			rows.Scan(&user.UserID, &user.HasUpload, &user.HasNewUpload)
			if res, _ := way.IsFileExist(path.Join("/app/upload", user.UserID)); res { // 错误数据检查 -- 是否有上传文件
				if user.HasUpload == 0 {
					user.HasUpload = 1
					utils.Db.Exec("update user_table set has_upload = 1 where userID = ?", user.UserID)
				}

				dst := path.Join("/app/upload", user.UserID)
				file, err := ioutil.ReadDir(dst)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{
						"msg": "error",
					})
					return
				}
				flag := 0
				for _, f := range file {
					if !f.IsDir() {
						fileName := f.Name()
						if fileName[0:3] == "new" { // 错误数据检查 -- 是否有新上传文件
							flag = 1
							break
						}
					}
				}
				if flag == 1 && user.HasNewUpload == 0 {
					utils.Db.Exec("update user_table set has_new_upload = 1 where userID = ?", user.UserID)
					user.HasNewUpload = 1
				} else if flag == 0 && user.HasNewUpload == 1 {
					user.HasNewUpload = 0
					utils.Db.Exec("update user_table set has_new_upload = 0 where userID = ?", user.UserID)
				}
			}
			users = append(users, user)
		}
	} else {
		c.JSON(http.StatusOK, users)
		return
	}

	var usersNumber int = len(users)
	var tmpUser []string = make([]string, usersNumber)
	var tmpScore []int = make([]int, usersNumber)

	sqlStr = "select userID, round(sum(solved_problem_score * magnification)) as 'totalScore' from problem_solved_table group by userID order by userID"

	rows, err = utils.Db.Query(sqlStr)
	if err == nil {
		i = 0
		for rows.Next() {
			rows.Scan(&tmpUser[i], &tmpScore[i])
			i++
		}
		for j := 0; j < usersNumber; j++ {
			for m := 0; m < i; m++ {
				if users[j].UserID == tmpUser[m] {
					users[j].TotalScore = tmpScore[m]
					sqlStr = "update user_table set score = ? where userID = ?"
					utils.Db.Exec(sqlStr, users[j].TotalScore, users[j].UserID)
					break
				}
			}
		}
	}

	sqlStr = "select userID, round(sum(solved_problem_score * magnification)) as 'webScore' from problem_solved_table where solved_problem_field = 0 group by userID order by userID"

	rows, err = utils.Db.Query(sqlStr)
	if err == nil {
		i = 0
		for rows.Next() {
			rows.Scan(&tmpUser[i], &tmpScore[i])
			i++
		}
		for j := 0; j < len(users); j++ {
			for m := 0; m < i; m++ {
				if users[j].UserID == tmpUser[m] {
					users[j].WebScore = tmpScore[m]
					break
				}
			}
		}
	}

	sqlStr = "select userID, round(sum(solved_problem_score * magnification)) as 'uiScore' from problem_solved_table where solved_problem_field = 1 group by userID order by userID"

	rows, err = utils.Db.Query(sqlStr)
	if err == nil {
		i = 0
		for rows.Next() {
			rows.Scan(&tmpUser[i], &tmpScore[i])
			i++
		}
		for j := 0; j < len(users); j++ {
			for m := 0; m < i; m++ {
				if users[j].UserID == tmpUser[m] {
					users[j].UIScore = tmpScore[m]
					break
				}
			}
		}
	}

	sqlStr = "select userID, round(sum(solved_problem_score * magnification)) as 'mlScore' from problem_solved_table where solved_problem_field = 2 group by userID order by userID"

	rows, err = utils.Db.Query(sqlStr)
	if err == nil {
		i = 0
		for rows.Next() {
			rows.Scan(&tmpUser[i], &tmpScore[i])
			i++
		}
		for j := 0; j < len(users); j++ {
			for m := 0; m < i; m++ {
				if users[j].UserID == tmpUser[m] {
					users[j].MLScore = tmpScore[m]
					break
				}
			}
		}
	}

	sqlStr = "select userID, round(sum(solved_problem_score * magnification)) as 'devScore' from problem_solved_table where solved_problem_field = 3 group by userID order by userID"

	rows, err = utils.Db.Query(sqlStr)
	if err == nil {
		i = 0
		for rows.Next() {
			rows.Scan(&tmpUser[i], &tmpScore[i])
			i++
		}
		for j := 0; j < len(users); j++ {
			for m := 0; m < i; m++ {
				if users[j].UserID == tmpUser[m] {
					users[j].DevScore = tmpScore[m]
					break
				}
			}
		}
	}

	sqlStr = "select userID, round(sum(solved_problem_score * magnification)) as 'securityScore' from problem_solved_table where solved_problem_field = 4 group by userID order by userID"

	rows, err = utils.Db.Query(sqlStr)
	if err == nil {
		i = 0
		for rows.Next() {
			rows.Scan(&tmpUser[i], &tmpScore[i])
			i++
		}
		for j := 0; j < len(users); j++ {
			for m := 0; m < i; m++ {
				if users[j].UserID == tmpUser[m] {
					users[j].SecurityScore = tmpScore[m]
					break
				}
			}
		}
	}

	sqlStr = "select userID, round(sum(solved_problem_score * magnification)) as 'basicScore' from problem_solved_table where solved_problem_field = 5 group by userID order by userID"

	rows, err = utils.Db.Query(sqlStr)
	if err == nil {
		i = 0
		for rows.Next() {
			rows.Scan(&tmpUser[i], &tmpScore[i])
			i++
		}
		for j := 0; j < len(users); j++ {
			for m := 0; m < i; m++ {
				if users[j].UserID == tmpUser[m] {
					users[j].BasicScore = tmpScore[m]
					break
				}
			}
		}
	}

	c.JSON(http.StatusOK, users)
}

func adminGetProblemUploadHandler(c *gin.Context) {

	var problemID int
	var upload model.Upload
	var uploads []model.Upload

	problemID, _ = strconv.Atoi(c.Param("problemID"))

	usersUploadDir, _ := ioutil.ReadDir("/app/upload")
	for _, userUploadDir := range usersUploadDir {
		flag := 0 // 判断是否是新上传的
		files, _ := ioutil.ReadDir(path.Join("/app/upload", userUploadDir.Name()))
		for _, file := range files {
			fileName := file.Name()
			if fileName[0:3] == "new" {
				fileName = fileName[4:]
				flag = 1
			}
			uploadProblemID, _ := strconv.Atoi(fileName[:strings.Index(fileName, "_")])
			if problemID == uploadProblemID {
				upload = way.SplitUploadFileNameToUploadType(fileName)
				if flag == 1 {
					upload.IsNewUpload = 1
				}
				uploads = append(uploads, upload)
			}
		}

	}

	c.JSON(http.StatusOK, uploads)
}

func guestCheckFlagHandler(c *gin.Context) {
	var submit struct {
		UserID    string `json:"userID"`
		Flag      string `json:"flag"`
		ProblemID int    `json:"problemID"`
	}
	var userSolved model.UserSolved
	var problem model.Problems
	var currentTime string
	var sqlStr string
	var row *sql.Row
	var hasSolved int
	var err error

	c.ShouldBind(&submit)
	currentTime = time.Now().String()
	currentTime = currentTime[:strings.Index(currentTime, ".")]

	sqlStr = "select count(*) from problem_solved_table where userID = ? and solved_problem_id = ?"
	utils.Db.QueryRow(sqlStr, submit.UserID, submit.ProblemID).Scan(&hasSolved)
	if hasSolved > 0 {
		c.JSON(http.StatusOK, gin.H{
			"msg": "has_solved",
		})
		return
	}
	sqlStr = "select problem_id, problem_title, problem_category, problem_score, current_score, flag, problem_solved from problem_table where problem_id = ?"
	row = utils.Db.QueryRow(sqlStr, submit.ProblemID)
	row.Scan(&problem.ProblemID, &problem.ProblemTitle, &problem.ProblemCategory, &problem.ProblemScore, &problem.CurrentScore, &problem.Flag, &problem.ProblemSolved)

	if problem.Flag == submit.Flag { // 正确flag
		sqlStr = "insert into problem_solved_table (userID, solved_problem_id, solved_problem_title, solved_problem_field, solved_problem_score, magnification, solved_problem_time) values (?, ?, ?, ?, ?, ?, ?)"
		_, err = utils.Db.Exec(sqlStr, submit.UserID, problem.ProblemID, problem.ProblemTitle, problem.ProblemCategory, problem.CurrentScore, 1, currentTime)
		if err != nil {
			fmt.Println(err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"msg": "error",
			})
			return
		}

		currentScore := way.CalculateCurrentScore(problem.ProblemScore, problem.ProblemSolved+1, 30)
		sqlStr = "update problem_table set problem_solved = problem_solved + 1, current_score = ? where problem_id = ?"
		_, err = utils.Db.Exec(sqlStr, currentScore, problem.ProblemID)
		if err != nil {
			fmt.Println(err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"msg": "error",
			})
			return
		}

		sqlStr = "update problem_solved_table set solved_problem_score = ? where solved_problem_id = ?" // 题目的最终得分是动态计算的
		_, err = utils.Db.Exec(sqlStr, currentScore, problem.ProblemID)
		if err != nil {
			fmt.Println(err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"msg": "error",
			})
			return
		}

		sqlStr = "update problem_table set first_blood = ? where problem_id = ? and first_blood = ''"
		res, err := utils.Db.Exec(sqlStr, submit.UserID, problem.ProblemID)
		rowsAffected, _ := res.RowsAffected()
		fmt.Println("firstblood ", rowsAffected)
		if err != nil {
			fmt.Println(err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"msg": "error",
			})
			return
		}

		sqlStr = "update user_table set problem_solved_number = problem_solved_number + 1 where userID = ?"
		_, err = utils.Db.Exec(sqlStr, submit.UserID)
		if err != nil {
			fmt.Println(err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"msg": "error",
			})
			return
		}

		var msg model.Message
		msg.Type = utils.MessageType["NEW_FLAG_SUBMIT"]
		msg.MsgData = model.MessageData{
			UserID: userSolved.UserID,
			Msg:    "new_flag",
			ProblemStatus: model.ProblemStatusInMessage{
				ProblemID:       submit.ProblemID,
				ProblemCategory: problem.ProblemCategory,
				ProblemTitle:    problem.ProblemTitle,
				OriginScore:     currentScore,
				Magnification:   1,
				IsFirstBlood:    rowsAffected > 0,
			},
		}
		model.Manager.Broadcast <- msg
		c.JSON(http.StatusOK, gin.H{
			"msg": "success",
		})
	} else {
		c.JSON(http.StatusOK, gin.H{
			"msg": "wrong_flag",
		})
	}
}

func guestUploadHandler(c *gin.Context) {
	var pre []string
	var userID string
	var problemID int
	var problemCategory string
	var problemTitle string
	var err error

	_, err = c.MultipartForm()
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"msg": "size_false",
		})
		return
	}
	file, err := c.FormFile("files")
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"msg": "file_false",
		})
		return
	}

	pre = c.Request.MultipartForm.Value["user"] // 提交人
	for _, name := range pre {
		userID = name
	}
	pre = c.Request.MultipartForm.Value["problemID"] // 提交题目id
	for _, name := range pre {
		problemID, err = strconv.Atoi(name)
	}
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "error",
		})
		return
	}
	pre = c.Request.MultipartForm.Value["problemTitle"] // 提交题目名
	for _, name := range pre {
		problemTitle = name
	}
	pre = c.Request.MultipartForm.Value["problemField"] // 题目所属方向
	for _, name := range pre {
		problemCategory = name
	}
	if userID == "" || problemID == 0 || problemTitle == "" || problemCategory == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "error",
		})
	}
	suffix := path.Ext(file.Filename)
	if strings.Compare(suffix, ".zip") != 0 && strings.Compare(suffix, ".doc") != 0 && strings.Compare(suffix, ".docx") != 0 && strings.Compare(suffix, ".pdf") != 0 && strings.Compare(suffix, ".rar") != 0 && strings.Compare(suffix, ".tar.gz") != 0 && strings.Compare(suffix, ".md") != 0 {
		c.JSON(http.StatusOK, gin.H{
			"msg": "suffix_false",
		})
		return
	}
	if res, _ := way.IsFileExist(path.Join("/app/upload", userID)); !res {
		res := way.CreateDir(userID)
		_, err = utils.Db.Exec("update user_table set has_upload = 1 where userID = ?", userID)
		if !res || err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"msg": "error",
			})
			return
		}
	}
	// 写入目录 例如:用户"su29029"提交的problemID为1 方向为web 题目名为"check in" 的题目，命名结果为"su29029_1_web_check_in.zip"
	fileName := strconv.Itoa(problemID) + "_" + userID + "_" + problemCategory + "_" + strings.Replace(problemTitle, " ", "_", -1)
	dst := path.Join("/app/upload", userID, "new_"+fileName+suffix)
	files, _ := ioutil.ReadDir(path.Join("/app/upload", userID))

	for _, f := range files {
		if strings.Contains(f.Name(), fileName) {
			os.Remove(path.Join("/app/upload", userID, f.Name()))
		}
	}

	err = c.SaveUploadedFile(file, dst)
	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"msg": "error",
		})
		return
	}
	_, err = utils.Db.Exec("update user_table set has_new_upload = 1 where userID = ?", userID)
	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"msg": "error",
		})
		return
	}
	fmt.Println("uploaded", file.Filename)

	var msg model.Message
	msg.Type = utils.MessageType["NEW_UPLOAD"]
	msg.MsgData = model.MessageData{
		UserID: userID,
		Msg:    "new_upload",
		ProblemStatus: model.ProblemStatusInMessage{
			ProblemID:       problemID,
			ProblemCategory: problemCategory,
			ProblemTitle:    problemTitle,
			OriginScore:     0,
			Magnification:   0,
			IsFirstBlood:    false,
		},
	}
	model.Manager.Broadcast <- msg
	c.JSON(http.StatusOK, gin.H{
		"msg": "succeed_upload",
	})
}

func guestGetUploadsHandler(c *gin.Context) {
	var problems []model.Problems
	var problem model.Problems
	var problemIDs []int
	var rows *sql.Rows
	var err error

	dst := path.Join("/app/upload", c.Param("userID"))
	if res, _ := way.IsFileExist(dst); !res {
		c.JSON(http.StatusOK, problems)
		return
	}
	file, err := ioutil.ReadDir(dst)
	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"msg": "error",
		})
		return
	}

	for _, f := range file {
		if !f.IsDir() {
			fileName := f.Name()
			if fileName[0:3] == "new" {
				fileName = fileName[4:]
			}
			index := strings.Index(fileName, "_")
			if index < 0 {
				c.JSON(http.StatusInternalServerError, gin.H{
					"msg": "error",
				})
				return
			}
			problemID, err := strconv.Atoi(fileName[:index])
			if err != nil {
				fmt.Println(err)
				c.JSON(http.StatusInternalServerError, gin.H{
					"msg": "error",
				})
				return
			}
			problemIDs = append(problemIDs, problemID)
		}
	}
	// 通过数据库查找出problemIDs对应的题目的题目名等信息
	query := fmt.Sprintf("select problem_id, problem_title, problem_category, problem_score, current_score, problem_solved from problem_table where problem_category = '"+c.Param("field")+"' and problem_id in (%s)", way.PlaceHolders(len(problemIDs)))

	rows, err = utils.Db.Query(query, way.TransferToInterface(problemIDs)...)

	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"msg": "error",
		})
		return
	}
	for rows.Next() {
		rows.Scan(&problem.ProblemID, &problem.ProblemTitle, &problem.ProblemCategory, &problem.ProblemScore, &problem.CurrentScore, &problem.ProblemSolved)
		problems = append(problems, problem)
	}
	c.JSON(http.StatusOK, problems)
}
