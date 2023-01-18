package services

import (
	"tunnel-provisioner-service/repositories"
)

type UsersService interface {
	Login(username, password string) error
	GetUserList() ([]string, error)
}

type UserServiceImpl struct {
	usersRepository repositories.UsersRepository
}

func NewUserService(usersRepository repositories.UsersRepository) *UserServiceImpl {
	return &UserServiceImpl{usersRepository: usersRepository}
}

func (u *UserServiceImpl) Login(username, password string) error {
	return u.usersRepository.Authenticate(username, password)
}

func (u *UserServiceImpl) GetUserList() ([]string, error) {
	return u.usersRepository.GetUserList()
}
