@echo off
setlocal enabledelayedexpansion

:: IntrDet - High-Performance Intrusion Detection Engine
:: Fixed Build Script for Windows

echo ========================================
echo IntrDet - Intrusion Detection Engine
echo ========================================
echo.

:: Check if we're in the project root directory
if not exist "CMakeLists.txt" (
    echo ERROR: CMakeLists.txt not found!
    echo Please run this script from the project root directory.
    pause
    exit /b 1
)

:: Set default values
set BUILD_TYPE=Release
set BUILD_DIR=build
set CLEAN_BUILD=false
set RUN_TESTS=false
set RUN_APP=false

:: Parse command line arguments
:parse_args
if "%1"=="" goto :end_parse
if /i "%1"=="--debug" set BUILD_TYPE=Debug
if /i "%1"=="--clean" set CLEAN_BUILD=true
if /i "%1"=="--test" set RUN_TESTS=true
if /i "%1"=="--run" set RUN_APP=true
if /i "%1"=="--help" goto :show_help
if /i "%1"=="-h" goto :show_help
shift
goto :parse_args
:end_parse

:: Check if g++ is available
where g++ >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: g++ not found! Please install MinGW-w64 or MSYS2.
    echo.
    echo Installation options:
    echo 1. Install MSYS2: https://www.msys2.org/
    echo 2. Add C:\msys64\mingw64\bin to your PATH
    echo 3. Restart your terminal
    echo.
    pause
    exit /b 1
)

:: Show current configuration
echo Build Configuration:
echo   Build Type: %BUILD_TYPE%
echo   Build Directory: %BUILD_DIR%
echo   Clean Build: %CLEAN_BUILD%
echo   Run Tests: %RUN_TESTS%
echo   Run Application: %RUN_APP%
echo.

:: Clean build directory if requested
if "%CLEAN_BUILD%"=="true" (
    echo Cleaning build directory...
    if exist "%BUILD_DIR%" (
        rmdir /s /q "%BUILD_DIR%"
        echo Build directory cleaned.
    )
    echo.
)

:: Create build directory
if not exist "%BUILD_DIR%" (
    echo Creating build directory...
    mkdir "%BUILD_DIR%"
)

:: Direct g++ compilation
echo Building with direct g++ compilation...
cd "%BUILD_DIR%"

:: Set compiler flags
if "%BUILD_TYPE%"=="Debug" (
    set CXXFLAGS=-g -Wall -Wextra -std=c++20
) else (
    set CXXFLAGS=-O3 -Wall -Wextra -std=c++20
)

:: Compile main application
echo Compiling IntrDet...
g++ %CXXFLAGS% -I../include -c ../src/main.cpp -o main.o
if %errorlevel% neq 0 (
    echo ERROR: Failed to compile main.cpp
    cd ..
    pause
    exit /b 1
)

g++ %CXXFLAGS% -I../include -c ../src/packet_sniffer.cpp -o packet_sniffer.o
if %errorlevel% neq 0 (
    echo ERROR: Failed to compile packet_sniffer.cpp
    cd ..
    pause
    exit /b 1
)

g++ %CXXFLAGS% -I../include -c ../src/packet_parser.cpp -o packet_parser.o
if %errorlevel% neq 0 (
    echo ERROR: Failed to compile packet_parser.cpp
    cd ..
    pause
    exit /b 1
)

g++ %CXXFLAGS% -I../include -c ../src/processing_pipeline.cpp -o processing_pipeline.o
if %errorlevel% neq 0 (
    echo ERROR: Failed to compile processing_pipeline.cpp
    cd ..
    pause
    exit /b 1
)

g++ %CXXFLAGS% -I../include -c ../src/anomaly_detector.cpp -o anomaly_detector.o
if %errorlevel% neq 0 (
    echo ERROR: Failed to compile anomaly_detector.cpp
    cd ..
    pause
    exit /b 1
)

g++ %CXXFLAGS% -I../include -c ../src/alert_manager.cpp -o alert_manager.o
if %errorlevel% neq 0 (
    echo ERROR: Failed to compile alert_manager.cpp
    cd ..
    pause
    exit /b 1
)

g++ %CXXFLAGS% -I../include -c ../src/mock_pcap.cpp -o mock_pcap.o
if %errorlevel% neq 0 (
    echo ERROR: Failed to compile mock_pcap.cpp
    cd ..
    pause
    exit /b 1
)

:: Link (using mock libraries)
echo Linking IntrDet...
g++ -o IntrDet.exe main.o packet_sniffer.o packet_parser.o processing_pipeline.o anomaly_detector.o alert_manager.o mock_pcap.o -lpthread -lws2_32

if %errorlevel% neq 0 (
    echo ERROR: Linking failed!
    echo.
    echo This might be due to missing system libraries.
    echo The application uses mock implementations for Boost and libpcap.
    echo.
    cd ..
    pause
    exit /b 1
)

cd ..

echo.
echo ========================================
echo Build completed successfully!
echo ========================================
echo.

:: Run tests if requested
if "%RUN_TESTS%"=="true" (
    echo Running tests...
    cd "%BUILD_DIR%"
    if exist "IntrDetTests.exe" (
        IntrDetTests.exe
    ) else (
        echo WARNING: Test executable not found!
        echo Tests require GoogleTest: pacman -S mingw-w64-x86_64-gtest
    )
    cd ..
    echo.
)

:: Run the application if requested
if "%RUN_APP%"=="true" (
    echo Starting IntrDet application...
    cd "%BUILD_DIR%"
    if exist "IntrDet.exe" (
        echo.
        echo ========================================
        echo IntrDet is starting...
        echo Press Ctrl+C to stop the application
        echo ========================================
        echo.
        IntrDet.exe
    ) else (
        echo ERROR: IntrDet executable not found!
        echo Expected location: %BUILD_DIR%\IntrDet.exe
    )
    cd ..
    echo.
)

:: Show available executables
echo Available executables in %BUILD_DIR%:
if exist "%BUILD_DIR%\IntrDet.exe" (
    echo   - IntrDet.exe (Main application)
)
if exist "%BUILD_DIR%\IntrDetTests.exe" (
    echo   - IntrDetTests.exe (Unit tests)
)

echo.
echo Build script completed.
pause
exit /b 0

:show_help
echo IntrDet Build Script
echo.
echo Usage: build_fixed.bat [options]
echo.
echo Options:
echo   --debug      Build in Debug mode (default: Release)
echo   --clean      Clean build directory before building
echo   --test       Run unit tests after building
echo   --run        Run the main application after building
echo   --help, -h   Show this help message
echo.
echo Examples:
echo   build_fixed.bat                    # Build in Release mode
echo   build_fixed.bat --debug --test     # Debug build and run tests
echo   build_fixed.bat --clean --run      # Clean build and run application
echo   build_fixed.bat --run              # Build and run immediately
echo.
echo Dependencies:
echo   - g++ (MinGW-w64/MSYS2)
echo   - libpcap: pacman -S mingw-w64-x86_64-libpcap
echo   - boost: pacman -S mingw-w64-x86_64-boost
echo   - gtest: pacman -S mingw-w64-x86_64-gtest (for tests)
echo.
pause
exit /b 0
