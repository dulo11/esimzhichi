# USIMS eSIM Fix

一个只针对 **USIMS (com.wonet.usims)** 的 LSPosed / libxposed API 102 模块。

## 功能
USIMS v3.90 的本地 eSIM 兼容判断位于：

`com.wonet.usims.helpers.i.d(android.content.Context): boolean`

本模块只在 USIMS 进程中把这个判断返回值改成 `true`，不修改其他 App，也不会把整个系统变成原生 eSIM 手机。

## 编译
仓库已经带 GitHub Actions。

1. 打开 **Actions**
2. 进入 **Build APK**
3. 点 **Run workflow**
4. 构建成功后在 Artifacts 下载 `USIMS-eSIM-Fix-v1.0.0`
5. 解压后安装 APK
6. LSPosed 启用模块，作用域只勾 **USIMS**
7. 重启手机

## 验证
```sh
su -c '/system/bin/logcat -c'
```

重新打开 USIMS 后：

```sh
su -c '/system/bin/logcat -d | grep -i USIMSeSIMFix'
```

正常会看到：

```text
Hook installed: com.wonet.usims.helpers.i.d(Context)
USIMS eSIM compatibility check -> forced TRUE
```

> 注意：此模块只绕过 USIMS 的“设备是否支持 eSIM”本地判断。手机没有真实 EuiccService/LPA 时，系统本身仍不会获得原生 eSIM 安装能力。
