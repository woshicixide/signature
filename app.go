package signature

import (
	"context"
)

type Secret interface {
	GetAppSecret(ctx context.Context) ([]string, error)
	GetAppid() string
	SetAppid(appid string)
}
