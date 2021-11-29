package signature

type Secret interface {
	GetAppSecret(appid string) ([]string, error)
}
