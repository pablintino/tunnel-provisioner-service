package services

import (
	"tunnel-provisioner-service/models"
	"tunnel-provisioner-service/repositories"
)

type UsersService interface {
	Login(username, password string) error
	GetUsers() (map[string]models.User, error)
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

func (u *UserServiceImpl) GetUsers() (map[string]models.User, error) {
	return u.usersRepository.GetUsers()
}
