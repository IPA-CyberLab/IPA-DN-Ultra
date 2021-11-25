SETLOCAL
SET BATCH_FILE_NAME=%0
SET BATCH_DIR_NAME=%0\..

for /f "usebackq tokens=*" %%i in (`"%BATCH_DIR_NAME%\BuildFiles\Utility\vswhere.exe" -version [17.0^,18.0^) -sort -requires Microsoft.Component.MSBuild -find Common7\Tools\VsDevCmd.bat`) do (
    if exist "%%i" (
        call "%%i"
    )
)

echo on


cd /d %BATCH_DIR_NAME%


msbuild /target:Clean /property:Configuration=Debug /property:Platform=x86 IPA-DN-Ultra-VS2022.sln
IF ERRORLEVEL 1 GOTO LABEL_ERROR

msbuild /verbosity:detailed /target:Rebuild /maxcpucount:8 /property:Configuration=Debug /property:Platform=x86 IPA-DN-Ultra-VS2022.sln
IF ERRORLEVEL 1 GOTO LABEL_ERROR



msbuild /target:Clean /property:Configuration=Debug /property:Platform=x64 IPA-DN-Ultra-VS2022.sln
IF ERRORLEVEL 1 GOTO LABEL_ERROR

msbuild /verbosity:detailed /target:Rebuild /maxcpucount:8 /property:Configuration=Debug /property:Platform=x64 IPA-DN-Ultra-VS2022.sln
IF ERRORLEVEL 1 GOTO LABEL_ERROR



msbuild /target:Clean /property:Configuration=Release /property:Platform=x86 IPA-DN-Ultra-VS2022.sln
IF ERRORLEVEL 1 GOTO LABEL_ERROR

msbuild /verbosity:detailed /target:Rebuild /maxcpucount:8 /property:Configuration=Release /property:Platform=x86 IPA-DN-Ultra-VS2022.sln
IF ERRORLEVEL 1 GOTO LABEL_ERROR



msbuild /target:Clean /property:Configuration=Release /property:Platform=x64 IPA-DN-Ultra-VS2022.sln
IF ERRORLEVEL 1 GOTO LABEL_ERROR

msbuild /verbosity:detailed /target:Rebuild /maxcpucount:8 /property:Configuration=Release /property:Platform=x64 IPA-DN-Ultra-VS2022.sln
IF ERRORLEVEL 1 GOTO LABEL_ERROR


:LABEL_ERROR



EXIT %ERRORLEVEL%


