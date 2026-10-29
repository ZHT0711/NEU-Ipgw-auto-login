## 自动认证东北大学校园网脚本C语言版本
javascript版本->https://github.com/CalebChen768/NEU_ipgw_login_js/tree/main
python脚本->https://github.com/CalebChen768/NEU-Ipgw-auto-login

### 1. 填写账号密码
复制 `config.example.ini` 为 `config.ini`，填写自己的统一登录账号密码。`config.ini` 已被 Git 忽略，请勿提交：

``` 
[info]
StudentID = 20001234
password = 12345678 
```

### 2. 自动触发
程序只匹配 `NEU`、`NEU-2.4G` 和 `NEU-mobile`。连接其他 Wi-Fi 时会立即退出；校园网已经能够访问互联网时也不会重复认证。

以 PowerShell 运行一次：

```powershell
powershell -ExecutionPolicy Bypass -File .\Install-AutoLoginTask.ps1
```

任务由 Windows 的 WLAN 连接事件触发，平时没有常驻进程和轮询。卸载任务：

```powershell
powershell -ExecutionPolicy Bypass -File .\Uninstall-AutoLoginTask.ps1
```

`Shortcuts.ahk` 是旧的定时轮询方案，安装上述计划任务后不要再运行它。

### 3. 环境要求
运行只需要 Windows 10/11。编译需要 GCC、OpenSSL、WinHTTP 和 Windows WLAN API。

### 4. 编译

```powershell
gcc -std=c17 -O2 AutoLogin.c -o AutoLogin.exe -lcrypto -lwinhttp -lwlanapi
```

计划任务会使用 `--scheduled` 参数隐藏窗口；手动双击运行时仍会显示结果。

## 最近更新
2026-08-28 初次commit，同时画一个ahk脚本的饼！
2026-09-01 增加 WLAN 事件触发、SSID 判断和联网状态检查。
