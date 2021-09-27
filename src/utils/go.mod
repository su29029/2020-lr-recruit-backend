module utils

go 1.14

require (
	github.com/go-sql-driver/mysql v1.5.0
	github.com/gorilla/websocket v1.4.1
	github.com/kataras/iris/v12 v12.1.8
	github.com/shurcooL/sanitized_anchor_name v1.0.0 // indirect
)

replace lrstudio.com/model => ../src/model

replace lrstudio.com/utils => ../src/utils

replace lrstudio.com/way => ../src/way
