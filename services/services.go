package services

import "errors"

var ErrServiceNotFoundEntity = errors.New("service entity not found")

type BooteableService interface {
	OnBoot() error
}

type DisposableService interface {
	OnClose() error
}
