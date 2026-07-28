@echo off && chcp 936
cls
cd /d "%~dp1"
del /f/q "%~n1.exe"
echo. ¿ªÊ¼±àÒë
call g++ -std=c++17 -Os -DNDEBUG -flto -s -ffunction-sections -fdata-sections -Wl,--gc-sections -static -static-libgcc -static-libstdc++ -o "%~n1.exe" %1
pause