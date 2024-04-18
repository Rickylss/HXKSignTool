@echo off
setlocal

dotnet build
dotnet publish -c Release

tar.exe -a -cf HCKSignTool.zip .\bin\Release\net4.0\publish
endlocal