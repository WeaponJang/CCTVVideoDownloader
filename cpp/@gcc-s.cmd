@echo off && chcp 65001
cls
cd /d "%~dp1"
del /f/q "dec.exe"
echo. 编译
call g++ -std=c++17 -Os -DNDEBUG -flto -s -ffunction-sections -fdata-sections -Wl,--gc-sections -static -static-libgcc -static-libstdc++ -o "dec.exe" dec.cpp
pause
