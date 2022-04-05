@echo off
chcp 65001 >nul 2>&1
echo ----------------------------------------------------------------
echo * Visual C++ 
echo * 清理Visual Studio工程中不需要的文件 
echo * 保存成.bat文件放置在工程目录中 
echo * 执行前先关闭打开该工程的Visual Studio 
echo * Author:kookol 
echo ----------------------------------------------------------------
pause
REM 删除debug或release一层目录下的pdb文件
REM for /f "delims=" %%i in ('dir /a-d /s /b ^| findstr /I "release\\[^\\]*.pdb$ debug\\[^\\]*.pdb$"') do (
REM 	echo %%i
REM 	del /F /Q "%%i" >nul 2>&1
REM )
REM 删除.vs目录
for /f "delims=" %%i in ('dir /ad /s /b ^| findstr /I "\\\.vs$"') do (
	echo %%i
	rd /Q /S %%i >nul 2>&1
)
REM 删除指定文件
del /F /Q /S *.idb >nul 2>&1
del /F /Q /S *.ipdb >nul 2>&1
del /F /Q /S *.obj >nul 2>&1
del /F /Q /S *.iobj >nul 2>&1
del /F /Q /S *.pch >nul 2>&1
del /F /Q /S *.ipch >nul 2>&1
del /F /Q /S *.aps >nul 2>&1
del /F /Q /S *.ncp >nul 2>&1
del /F /Q /S *.sbr >nul 2>&1
del /F /Q /S *.tmp >nul 2>&1
del /F /Q /S *.bsc >nul 2>&1
del /F /Q /S *.ilk >nul 2>&1
del /F /Q /S *.res >nul 2>&1
del /F /Q /S *.ncb >nul 2>&1
del /F /Q /S *.suo >nul 2>&1
del /F /Q /S *.dep >nul 2>&1
del /F /Q /S *.sdf >nul 2>&1
del /F /Q /S *.plg >nul 2>&1
del /F /Q /S *.tlb >nul 2>&1
del /F /Q /S *.tlh >nul 2>&1
del /F /Q /S *.tli >nul 2>&1
del /F /Q /S *.clw >nul 2>&1
del /F /Q /S *.tlog >nul 2>&1
del /F /Q /S *.lastbuildstate >nul 2>&1
REM del /F /Q /S *.manifest >nul 2>&1
REM del /F /Q /S *.opt >nul 2>&1
REM del /F /Q /S *.user >nul 2>&1
REM del /F /Q /S *.pdb >nul 2>&1
REM del /F /Q /S Release\*.pdb >nul 2>&1
REM del /F /Q /S Debug\*.pdb >nul 2>&1
REM del /F /Q /S Release\*.map >nul 2>&1
REM del /F /Q /S Debug\*.map >nul 2>&1

echo 文件清理完毕！！！
pause