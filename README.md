# HCKSignTool

## Build
```powershell
#构建
dotnet build

#打包
dotnet publish -c Release

#或者直接使用 `build.bat` 脚本直接生成 `HCKSignTool.zip`
build.bat
```

## Usage

解压 `HCKSignTool.zip`

```powershell
# 生成签名
HCKSignTool.exe -k "xxx.hckx" -c "xxx.cert"
```

# REFERENCE
[code-sample](https://learn.microsoft.com/en-us/windows-hardware/test/hlk/user/hlk-signing-with-an-hsm#code-samples)