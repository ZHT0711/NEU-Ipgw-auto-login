; =====================================================
; 自动运行 exe 当连接到包含 "NEU" 的网络时
; 请修改下面的变量以匹配你的需求
; 推荐使用ahk2.0版本进行编译
; =====================================================

#Persistent                        ; 保持脚本运行
#SingleInstance, Force             ; 只允许一个实例

; --- 用户设置区域 ---
ExePath := "C:\Path\To\AutoLogin.exe"   ; 替换为你自己的 exe 完整路径
ExeProcessName := "AutoLogin.exe"       ; 可选：进程名（用于防止重复运行），留空则不检查
CheckInterval := 5000                      ; 检查间隔（毫秒），默认5秒

; --- 内部变量 ---
exeHasRun := false                 ; 标记 exe 是否已在当前网络连接中运行过
lastNetworkName := ""              ; 记录上一次检测到的网络名称

; --- 启动定时器 ---
SetTimer, CheckNetwork, %CheckInterval%
return

CheckNetwork:
    ; 使用 PowerShell 获取当前活动的网络连接名称（适用于 Wi-Fi 和有线）
    ; 如果系统没有 PowerShell 或命令失败，则跳过本次检查
    RunWait, powershell -NoProfile -Command "(Get-NetConnectionProfile).Name", , Hide, OutputVarPID
    ; 注意：RunWait 会等待命令完成，但输出无法直接捕获到变量，因此改用下面方式
    ; 上述写法有误，我们改用更可靠的方式：
    
    ; 创建临时文件来存储输出
    tempFile := A_Temp . "\netname.tmp"
    FileDelete, %tempFile%
    RunWait, %ComSpec% /c "powershell -NoProfile -Command "(Get-NetConnectionProfile).Name" > "%tempFile%"", , Hide
    
    if (ErrorLevel != 0) {
        ; 命令执行失败，可能没有网络或 PowerShell 问题，重置标志
        exeHasRun := false
        lastNetworkName := ""
        return
    }
    
    ; 读取输出
    FileRead, netName, %tempFile%
    FileDelete, %tempFile%
    
    ; 去除空白字符
    netName := Trim(netName)
    
    ; 如果网络名称没有变化，则无需处理（避免重复检查）
    if (netName = lastNetworkName)
        return
    lastNetworkName := netName
    
    ; 检查网络名称是否包含 "NEU"（不区分大小写）
    if (InStr(netName, "NEU", false)) {
        ; 如果还未运行过 exe，则运行
        if (!exeHasRun) {
            ; 可选：检查进程是否已在运行（防止重复启动）
            shouldRun := true
            if (ExeProcessName != "") {
                Process, Exist, %ExeProcessName%
                if (ErrorLevel > 0) {
                    ; 进程已存在，跳过运行
                    shouldRun := false
                }
            }
            
            if (shouldRun) {
                Run, "%ExePath%"
                ; 可选：弹出提示
                TrayTip, 网络触发, 检测到 %netName% 网络，已启动程序。, , 1
                exeHasRun := true
            }
        }
    } else {
        ; 网络不匹配，重置标志，以便下次连接时再次运行
        exeHasRun := false
    }
return