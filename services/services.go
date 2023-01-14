package services

type BooteableService interface {
	OnBoot() error
}
