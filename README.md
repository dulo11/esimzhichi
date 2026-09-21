# USIMS eSIM Fix

只作用于 **USIMS (com.wonet.usims)** 的 LSPosed / libxposed API 102 模块。

## v1.2.0

在继续强制 USIMS 本地 eSIM 检测为 true 的基础上，加入完整诊断：

- USIMS 版本、versionCode、安装来源、签名证书 SHA-256
- Google Play 商店 / Google Play services / GSF 版本
- Build manufacturer / brand / model / device / product
- fingerprint / hardware / board / bootloader / type / tags / Android 版本 / 安全补丁 / ABI
- eUICC feature、EuiccManager 是否存在、isEnabled
- 关键硬件 feature
- Android ID 仅记录长度和 SHA-256 前缀，不记录原值
- Widevine Device Unique ID 仅记录长度和 SHA-256 前缀，不记录原值
- SIM / 网络国家、运营商、phoneType、SIM 状态
- Locale / TimeZone / HTTP agent
- 关键 Android system properties，用于发现 Device Faker 只改 Build 但底层 prop 仍泄露真实机型的情况
- Hook OkHttp Request.Builder，遇到 routeLoginCall 时打印服务端真正收到的登录字段
- phone / device_id / MediaDRM ID / captcha token 自动脱敏，不输出原值
- HTTP Header 中 Authorization / Cookie / Token / Secret / API key / Signature 自动脱敏

## 重点日志

安装并重启后：

```sh
su -c '/system/bin/logcat -c'
```

打开 USIMS，点一次登录，然后：

```sh
su -c '/system/bin/logcat -d | grep -i USIMSeSIMFix'
```

如果日志太多：

```sh
su -c '/system/bin/logcat -d | grep -i -E "USIMSeSIMFix.*(APP |BUILD|ANDROID|ESIM|FEATURES|ID |TEL |LOCALE|PROP |REQ |BODY |HDR |routeLoginCall|original=)"'
```

正常会看到：

```text
APP package=com.wonet.usims ...
BUILD manufacturer=Google brand=Google model=GXQ96 device=tegu product=tegu
ESIM euiccFeature=true euiccService=present,isEnabled=true
USIMS eSIM compatibility original=... -> forced TRUE

========== routeLoginCall BEGIN ==========
REQ phone=<redacted ...>
REQ phone_brand=...
REQ phone_type=...
REQ phone_manufacturer=...
REQ phone_esim_compatible=...
REQ phone_app_version=...
REQ device_id=<len=... sha256=...>
REQ phone_mediadrm_id=<len=... sha256=...>
REQ captcha_token=<present len=... sha256=...>
========== routeLoginCall END ==========
```

## 注意

这个模块不会把手机真正变成原生 eSIM 设备。它只：

1. 绕过 USIMS 自己的本地兼容判断；
2. 记录 USIMS 在本机看到的环境；
3. 记录 routeLoginCall 即将提交的关键字段，敏感值会自动脱敏。

服务器端仍可能根据 Play Integrity 的 appIntegrity / licensing、设备 ID、MediaDRM、账号状态、风控、版本门槛或其他服务端规则拒绝请求。
