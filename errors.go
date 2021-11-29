package signature

import "errors"

var ErrParseParamFail = errors.New("参数解析错误")
var ErrNoSignature = errors.New("缺少签名")
var ErrNoAppId = errors.New("缺少AppId")
var ErrNoAppSecret = errors.New("缺少AppSecret")
var ErrNoTimeField = errors.New("缺少时间参数")
var ErrTimeExpire = errors.New("已过期")
var ErrCheckFail = errors.New("校验失败")
