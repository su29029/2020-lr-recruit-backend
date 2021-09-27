module main

go 1.14

require lrstudio.com/model v0.0.0-incompatible

require (
	github.com/aliyun/alibaba-cloud-sdk-go v1.61.481
	github.com/garyburd/redigo v1.6.2
	github.com/gin-contrib/sessions v0.0.3
	github.com/gin-gonic/gin v1.6.3
	github.com/go-sql-driver/mysql v1.5.0
	github.com/gorilla/websocket v1.4.2
	lrstudio.com/utils v0.0.0-incompatible
	lrstudio.com/way v0.0.0-00010101000000-000000000000
)

replace lrstudio.com/model => ./src/model

replace lrstudio.com/utils => ./src/utils

replace lrstudio.com/way => ./src/way
