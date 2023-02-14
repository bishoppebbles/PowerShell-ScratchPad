'Task manager name: Microsoft Windows Based Script Host
'cscript.exe sendkeys.vbs
'tasklist /fi "imagename eq cscript.exe"
'taskkill /F /IM cscript.exe
'NOTE: program could alternatively be called wscript.exe (usually the default)

Set WshShell = WScript.CreateObject("WScript.Shell")
WshShell.Run "%windir%\notepad.exe"
WScript.Sleep 1000
WshShell.AppActivate "Notepad"

While True
   WshShell.SendKeys "{RIGHT}"
   WScript.Sleep 30000   'NOTE: crucial to sleep or you'll likely DOS your Windows session
Wend