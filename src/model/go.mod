module model

go 1.14

require (
	github.com/gorilla/websocket v1.4.2
	lrstudio.com/utils v0.0.0-00010101000000-000000000000
	lrstudio.com/way v0.0.0-00010101000000-000000000000
	lrstudio.com/model v0.0.0-00010101000000-000000000000
)

replace lrstudio.com/model => ../model

replace lrstudio.com/utils => ../utils

replace lrstudio.com/way => ../way
