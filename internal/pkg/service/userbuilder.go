package service

import (
	"fmt"

	api "github.com/GoAsyncFunc/uniproxy/pkg"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/trojan"
)

func buildUser(tag string, userInfo []api.UserInfo) (users []*protocol.User) {
	for _, user := range userInfo {
		trojanAccount := &trojan.Account{
			Password: user.Uuid,
		}
		account := serial.ToTypedMessage(trojanAccount)
		u := &protocol.User{
			Level:   0,
			Email:   buildUserEmail(tag, user.Id, user.Uuid),
			Account: account,
		}
		users = append(users, u)
	}
	return users
}

func buildUserEmail(tag string, uid int, uuid string) string {
	return fmt.Sprintf("%s|%d|%s", tag, uid, uuid)
}
