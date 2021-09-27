package model

import (
	"sync"

	"fmt"
	"runtime/debug"

	"github.com/gorilla/websocket"

	"lrstudio.com/utils"
)

// ClientManager 管理所有连接的客户端
type ClientManager struct {
	Clients     map[*Client]bool   //all connections  Im.the clients' ips
	Users       map[string]*Client //login users  Im.the users' ids
	Connect     chan *Client
	Disconnect  chan *Client
	ClientsLock sync.RWMutex
	UsersLock   sync.RWMutex
	Broadcast   chan Message //sending channel
}

// Client 管理单个连接的客户端的相关数据
type Client struct {
	UserID string
	Addr   string
	Socket *websocket.Conn
	Send   chan Message
}

var Manager *ClientManager

func init() {
	Manager = newClientManager()
	go Manager.start()
}

func newClientManager() (manager *ClientManager) {
	manager = &ClientManager{
		Clients:   make(map[*Client]bool),
		Users:     make(map[string]*Client),
		Connect:   make(chan *Client, 1000),
		Broadcast: make(chan Message, 1000),
	}
	return
}

func (c *Client) Read() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("read stop", string(debug.Stack()), r)
		}
	}()

	defer func() {
		Manager.Disconnect <- c
	}()

	for {
		var message Message
		err := c.Socket.ReadJSON(&message)
		if err != nil {
			fmt.Println("读取数据错误", c.Addr, err)
			return
		}

		ProcessWsData(c, message)
	}
}

func (c *Client) Write() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("write stop", string(debug.Stack()), r)
		}
	}()
	defer func() {
		Manager.Disconnect <- c
		// c.Socket.Close()
	}()

	for {
		select {
		case message, ok := <-c.Send:
			if !ok {
				fmt.Println("发送数据错误:", c.UserID)
				return
			}

			fmt.Println("write: ", message)
			c.Socket.WriteJSON(message)
		}
	}
}

// SendMsg ...
// send message to a certain client
func (c *Client) SendMsg(msg Message) {
	c.Send <- msg
	fmt.Println("Send:", msg.MsgData.UserID)
}

// EventConnect ...
// Deal with a connect event
func (manager *ClientManager) EventConnect(client *Client) {
	Manager.AddClients(client)
	fmt.Println("加入连接:", client.UserID)
}

// EventDisconnect ...
// Deal with a disconnect event
func (manager *ClientManager) EventDisconnect(client *Client) {
	Manager.DeleteClients(client)
	fmt.Println("断开连接:", client.UserID)
}

// AddClients ...
// Add a new client when there is a new connection
func (manager *ClientManager) AddClients(client *Client) {
	manager.ClientsLock.Lock()
	defer manager.ClientsLock.Unlock()

	Manager.Clients[client] = true
}

// GetClients ...
// Get all connected clients
func (manager *ClientManager) GetClients() (clients map[*Client]bool) {
	clients = make(map[*Client]bool)
	manager.ClientsLock.RLock()
	defer manager.ClientsLock.RUnlock()

	manager.ClientsRange(func(client *Client, value bool) (result bool) {
		clients[client] = value

		return true
	})

	return
}

// ClientsRange ...
// range all clients
func (manager *ClientManager) ClientsRange(f func(client *Client, value bool) (result bool)) {
	manager.ClientsLock.RLock()
	defer manager.ClientsLock.RUnlock()

	for key, value := range Manager.Clients {
		result := f(key, value)
		if result == false {
			return
		}
	}
}

// DeleteClients ...
// delete the disconnected client when a client is disconnected
func (manager *ClientManager) DeleteClients(client *Client) {
	manager.ClientsLock.Lock()
	defer manager.ClientsLock.Unlock()
	for key, value := range Manager.Clients {
		fmt.Println("key:", key, "value:", value)
	}
	delete(Manager.Clients, client)
	for key, value := range Manager.Clients {
		fmt.Println("key:", key, "value:", value)
	}
}

// ProcessWsData ...
// deal with data from client
func ProcessWsData(client *Client, message Message) {
	var msg Message
	msg.Type = message.Type
	switch message.Type {
	case utils.MessageType["HEART_BEAT"]:
		msg.MsgData.Msg = "pong"
		client.SendMsg(msg)
	case utils.MessageType["NEW_PROBLEM"]:
		msg.MsgData.UserID = message.MsgData.UserID
		msg.MsgData.Msg = "new_problem"
		msg.MsgData.ProblemStatus = message.MsgData.ProblemStatus
		Manager.Broadcast <- msg
	case utils.MessageType["NEW_UPLOAD"]:
		msg.MsgData.UserID = message.MsgData.UserID
		msg.MsgData.Msg = "new_upload"
		msg.MsgData.ProblemStatus = message.MsgData.ProblemStatus
		Manager.Broadcast <- msg
	case utils.MessageType["NEW_FLAG_SUBMIT"]:
		msg.MsgData.UserID = message.MsgData.UserID
		msg.MsgData.Msg = "new_flag"
		msg.MsgData.ProblemStatus = message.MsgData.ProblemStatus
		Manager.Broadcast <- msg
	case utils.MessageType["CORRECT_ANSWER"]:
		msg.MsgData.UserID = message.MsgData.UserID
		msg.MsgData.Msg = "correct_answer"
		msg.MsgData.ProblemStatus = message.MsgData.ProblemStatus
		Manager.Broadcast <- msg
	case utils.MessageType["ERROR"]:
		msg.MsgData.Msg = "error"
		client.SendMsg(msg)
		Manager.Disconnect <- client
	}
}

// start ...
// main dealing and task distribute function
func (manager *ClientManager) start() {
	for {
		select {
		case conn := <-manager.Connect:
			manager.EventConnect(conn)
		case conn := <-manager.Disconnect:
			manager.EventDisconnect(conn)
		case message := <-manager.Broadcast: // first,get all clients,second,use channel to send messages.
			clients := manager.GetClients()
			for conn := range clients { // use channel, in order to ensure thread safety.
				//TODO:use channel to send messages.
				select {
				case conn.Send <- message:
				default:
					close(conn.Send)
				}
			}
		}
	}
}
