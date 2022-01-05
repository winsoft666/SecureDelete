/*******************************************************************************
 * Copyright (C) 2022 - 2024, winsoft666, <winsoft666@outlook.com>.
 *
 * THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
 * EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
 *
 * Expect bugs
 *
 * Please use and enjoy. Please let me know of any bugs/improvements
 * that you have found/implemented and I will fix/incorporate them into this
 * file.
 *******************************************************************************/

#ifndef _SECURE_DELETE_H_
#define _SECURE_DELETE_H_
#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// SecureDelete implements a secure delete function for Windows NT/2K. 
// It even works on WinNT compressed, encrypted and sparse files.
//
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
class SecureDelete {
public:
    enum class FillMode {
        Zero = 0,
        Random = 1,
    };
    SecureDelete(FillMode fillMode = FillMode::Zero);
    virtual ~SecureDelete();

    bool isSecureSupported() const;
    bool deleteFile(const wchar_t* pszFilePath, DWORD dwNumPasses = 1);
    bool deleteDirectory(const wchar_t* pszDirectoryPath, DWORD dwNumPasses = 1, bool breakWhenError = false);
protected:
    bool secureDeleteCompressed(const wchar_t* pszFilePath, DWORD dwNumPasses);
    bool scanFile(HANDLE hVolumeHandle, DWORD dwClusterSize, HANDLE hFileHandle, bool* pReallyCompressed, bool* pZappedFile, DWORD dwNumPasses);
    bool doSecureDelete(const wchar_t* pszFilePath, long FileLengthHi, unsigned long FileLengthLo, DWORD dwNumPasses);
    bool overwriteFile(HANDLE hFileHandle, unsigned __int64 Length, DWORD dwNumPasses);
    bool overwriteFileName(const wchar_t* pszFilePath, wchar_t* pszLastFilePath);
protected:
    FillMode fillMode_;
    bool isSecureSupported_;
    PBYTE fillBuffer_;
};

#endif //!_SECURE_DELETE_H_
