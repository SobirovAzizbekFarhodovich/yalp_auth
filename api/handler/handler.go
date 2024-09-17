package handler

import (
	pb "auth/genprotos"
	"auth/storage"
	r "auth/storage/redis"
)

type Handler struct {
	UserStorage storage.StorageI
	User        pb.UserServiceClient
	redis       r.InMemoryStorageI
}

func NewHandler(us pb.UserServiceClient, rdb r.InMemoryStorageI, userStorage storage.StorageI) *Handler {
	return &Handler{userStorage, us, rdb}
}
