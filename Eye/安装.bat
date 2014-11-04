@echo off

set dllPath="C:\Program Files\Fiddler2\Scripts\Eye.dll"
set settingsPath="C:\Program Files\Fiddler2\Scripts\eye"

copy Eye.dll %dllPath%
md %settingsPath%
xcopy /e .\eye %settingsPath%

echo 安装成功

pause&exit