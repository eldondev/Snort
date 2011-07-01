@echo off

REM $Id: build_releases.bat,v 1.3 2004/01/14 04:12:00 chris_reid Exp $

REM -- --------------------------------------------------------------
REM -- If you are having problems running "NMAKE", you probably
REM -- haven't configured the proper paths.  Uncomment the following
REM -- line to help configure this properly.  You will need to update
REM -- the line to reflect whichever drive/path you specified when
REM -- installing Visual C++ 6.0.
REM -- --------------------------------------------------------------
REM call "C:\Program Files\Microsoft Visual Studio\VC98\Bin\vcvars32.bat"


DEL snort___Win32_MySQL_Release\snort.exe
DEL snort___Win32_SQLServer_Release\snort.exe
DEL snort___Win32_Oracle_Release\snort.exe


NMAKE /f "snort.mak" CFG="snort - Win32 MySQL Release"

NMAKE /f "snort.mak" CFG="snort - Win32 SQLServer Release"

NMAKE /f "snort.mak" CFG="snort - Win32 Oracle Release"
