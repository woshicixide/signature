package signature

import (
	"crypto/md5"
	"encoding/hex"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// 默认五分钟过期
const defaultExpire = 5 * 60 * time.Second

type Md5Verifier struct {
	secrets  Secret //appData允许有多个
	expire   time.Duration
	paramStr string
}

// 初始化一个校验器
func NewMd5Verifier(paramStr string, secrets Secret) *Md5Verifier {
	return &Md5Verifier{
		secrets:  secrets,
		expire:   defaultExpire,
		paramStr: paramStr,
	}
}

// 设置过期时间
func (v *Md5Verifier) SetExpire(t time.Duration) *Md5Verifier {
	v.expire = t
	return v
}

// 参数检查&&校验
func (v *Md5Verifier) Check() error {
	// 解析参数
	u, err := url.Parse(v.paramStr)
	if err != nil {
		return ErrParseParamFail
	}
	values, err := url.ParseQuery(u.RawQuery)
	if nil != err {
		return ErrParseParamFail
	}

	// 校验时间参数是否存在
	if !values.Has("Timestamp") {
		return ErrNoTimeField
	}
	// 校验请求是否过期
	ts, err := strconv.ParseInt(values.Get("Timestamp"), 10, 64)
	if nil != err {
		return ErrNoTimeField
	}
	if (ts + int64(v.expire)) < time.Now().Unix() {
		return ErrTimeExpire
	}

	// 校验appid
	if !values.Has("AppId") {
		return ErrNoAppId
	}
	// 校验签名是否存在
	if !values.Has("Signature") {
		return ErrNoSignature
	}

	// 排除参数后期再考虑吧

	// 获取appsecret
	appid := values.Get("AppId")
	v.secrets.SetAppid(appid)
	ss, err := v.secrets.GetAppSecret()
	if err != nil {
		return ErrNoAppSecret
	}

	signature := values.Get("Signature")
	values.Del("Signature")

	for i := 0; i < len(ss); i++ {
		tmp := values
		tmp.Add("AddSecret", ss[i])
		if signature == check(tmp) {
			return nil
		}

	}
	return ErrCheckFail
}

// 校验
func check(values url.Values) string {
	fields := make([]string, len(values))
	for k := range values {
		fields = append(fields, k)
	}
	sort.Strings(fields)

	vs := make([]string, len(fields))
	for i := 0; i < len(fields); i++ {
		vs = append(vs, values.Get(fields[i]))
	}

	return md5Encrypt(strings.Join(vs, ""))
}

// md5加密
func md5Encrypt(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}
