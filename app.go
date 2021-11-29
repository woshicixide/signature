package signature

type Secret interface {
	GetAppSecret() ([]string, error)
	GetAppid() string
	SetAppid(appid string)
}
