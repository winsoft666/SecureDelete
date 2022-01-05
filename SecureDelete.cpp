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

#define _CRT_SECURE_NO_DEPRECATE
#include <tchar.h>
#include <stdio.h>
#include <time.h>
#include <strsafe.h>
#include <Shlwapi.h>
#include "SecureDelete.h"
#include <VersionHelpers.h>

#pragma comment(lib, "Shlwapi.lib")

#define LLINVALID ((ULONGLONG)-1)
#define FILEMAPSIZE (16384 + 2)
#define CLEANBUFSIZE 65536

namespace {
    //====================================================================
    //
    // Defrag.h
    // Header file for defragmentation demonstration program. This file
    // includes definitions for defragmentation File System Control
    // commands, as well as the undocumented NtFsControl call.
    //
    //====================================================================

    //--------------------------------------------------------------------
    //                     D E F I N E S
    //--------------------------------------------------------------------

    //
    // File System Control commands related to defragging
    //
#define FSCTL_GET_VOLUME_INFORMATION 0x90064
#define FSCTL_READ_MFT_RECORD 0x90068
#ifndef FSCTL_GET_VOLUME_BITMAP
#define FSCTL_GET_VOLUME_BITMAP 0x9006F
#endif
#ifndef FSCTL_GET_RETRIEVAL_POINTERS
#define FSCTL_GET_RETRIEVAL_POINTERS 0x90073
#endif
#ifndef FSCTL_GET_VOLUME_BITMAP
#define FSCTL_GET_VOLUME_BITMAP 0x90074
#endif

//
// return code type
//
//typedef UINT NTSTATUS;

//
// Error codes returned by NtFsControlFile (see NTSTATUS.H)
//
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define STATUS_BUFFER_OVERFLOW ((NTSTATUS)0x80000005L)
#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xC000000DL)
#endif
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023L)
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000011L)
#define STATUS_ALREADY_COMMITTED ((NTSTATUS)0xC0000021L)
#define STATUS_INVALID_DEVICE_REQUEST ((NTSTATUS)0xC0000010L)

//--------------------------------------------------------------------
//       F S C T L  S P E C I F I C   T Y P E D E F S
//--------------------------------------------------------------------

//
// This is the definition for a VCN/LCN (virtual cluster/logical cluster)
// mapping pair that is returned in the buffer passed to
// FSCTL_GET_RETRIEVAL_POINTERS
//
    typedef struct {
        ULONGLONG Vcn;
        ULONGLONG Lcn;
    } MAPPING_PAIR, * PMAPPING_PAIR;

    //
    // This is the definition for the buffer that FSCTL_GET_RETRIEVAL_POINTERS
    // returns. It consists of a header followed by mapping pairs
    //
    typedef struct {
        ULONG NumberOfPairs;
        ULONGLONG StartVcn;
        MAPPING_PAIR Pair[1];
    } GET_RETRIEVAL_DESCRIPTOR, * PGET_RETRIEVAL_DESCRIPTOR;

    //
    // This is the definition of the buffer that FSCTL_GET_VOLUME_BITMAP
    // returns. It consists of a header followed by the actual bitmap data
    //
    typedef struct {
        ULONGLONG StartLcn;
        ULONGLONG ClustersToEndOfVol;
        BYTE Map[1];
    } BITMAP_DESCRIPTOR, * PBITMAP_DESCRIPTOR;

    //
    // This is the definition for the data structure that is passed in to
    // FSCTL_MOVE_FILE
    //
    typedef struct {
        HANDLE FileHandle;
        ULONG Reserved;
        ULONGLONG StartVcn;
        ULONGLONG TargetLcn;
        ULONG NumVcns;
        ULONG Reserved1;
    } MOVEFILE_DESCRIPTOR, * PMOVEFILE_DESCRIPTOR;

    //
    // NTFS volume information
    //
    /*
    typedef struct {
        ULONGLONG    	SerialNumber;
        ULONGLONG    	NumberOfSectors;
        ULONGLONG    	TotalClusters;
        ULONGLONG    	FreeClusters;
        ULONGLONG    	Reserved;
        ULONG    		BytesPerSector;
        ULONG    		BytesPerCluster;
        ULONG    		BytesPerMFTRecord;
        ULONG    		ClustersPerMFTRecord;
        ULONGLONG    	MFTLength;
        ULONGLONG    	MFTStart;
        ULONGLONG    	MFTMirrorStart;
        ULONGLONG    	MFTZoneStart;
        ULONGLONG    	MFTZoneEnd;
    } NTFS_VOLUME_DATA_BUFFER, *PNTFS_VOLUME_DATA_BUFFER;
    */

    //--------------------------------------------------------------------
    //     N T F S C O N T R O L F I L E   D E F I N I T I O N S
    //--------------------------------------------------------------------

    //
    // Prototype for NtFsControlFile and data structures
    // used in its definition
    //

    //
    // Io Status block (see NTDDK.H)
    //
    typedef struct _IO_STATUS_BLOCK {
        NTSTATUS Status;
        ULONG Information;
    } IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

    //
    // Apc Routine (see NTDDK.H)
    //
    typedef VOID(*PIO_APC_ROUTINE)(
        PVOID ApcContext,
        PIO_STATUS_BLOCK IoStatusBlock,
        ULONG Reserved);

    //
    // The undocumented NtFsControlFile
    //
    // This function is used to send File System Control (FSCTL)
    // commands into file system drivers. Its definition is
    // in ntdll.dll (ntdll.lib), a file shipped with the NTDDK.
    //
    NTSTATUS(__stdcall* NtFsControlFile)
        (
            HANDLE FileHandle,
            HANDLE Event,                // optional
            PIO_APC_ROUTINE ApcRoutine,  // optional
            PVOID ApcContext,            // optional
            PIO_STATUS_BLOCK IoStatusBlock,
            ULONG FsControlCode,
            PVOID InputBuffer,  // optional
            ULONG InputBufferLength,
            PVOID OutputBuffer,  // optional
            ULONG OutputBufferLength);

    ULONG(__stdcall* RtlNtStatusToDosError)
        (
            IN NTSTATUS Status);

    //====================================================================
}  // namespace

SecureDelete::SecureDelete(FillMode fillMode) :
    fillMode_(fillMode),
    isSecureSupported_(false),
    fillBuffer_(NULL) {
    do {
        // If we're on Win9x, just return
        if (!IsWindowsXPOrGreater()) {
            break;
        }

        // Load the NTDLL entry point we need
        if (!(NtFsControlFile = (NTSTATUS(__stdcall*)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG))
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtFsControlFile"))) {
            break;
        }

        if (!(RtlNtStatusToDosError = (ULONG(__stdcall*)(NTSTATUS))GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlNtStatusToDosError"))) {
            break;
        }

        isSecureSupported_ = true;
    } while (false);

    if (isSecureSupported_) {
        fillBuffer_ = (PBYTE)VirtualAlloc(NULL, CLEANBUFSIZE, MEM_COMMIT, PAGE_READWRITE);
        if (fillBuffer_) {
            if (fillMode_ == FillMode::Zero) {
                memset(fillBuffer_, 0, CLEANBUFSIZE);
            }
            else if (fillMode_ == FillMode::Random) {
                srand((unsigned int)time(NULL));
                for (DWORD j = 0; j < CLEANBUFSIZE; j++) {
                    fillBuffer_[j] = (BYTE)rand();
                }
            }
        }
    }
}

SecureDelete::~SecureDelete() {
    if (fillBuffer_) {
        VirtualFree(fillBuffer_, 0, MEM_RELEASE);
        fillBuffer_ = NULL;
    }
}

bool SecureDelete::isSecureSupported() const {
    return isSecureSupported_;
}

bool SecureDelete::deleteFile(const wchar_t* pszFilePath, DWORD dwNumPasses) {
    if (!pszFilePath)
        return false;

    if (isSecureSupported_ && dwNumPasses > 0) {
        SetFileAttributesW(pszFilePath, FILE_ATTRIBUTE_NORMAL);

        DWORD dwFileAttributes = GetFileAttributesW(pszFilePath);
        if ((dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || (dwFileAttributes == 0xFFFFFFFF)) {
            return false;
        }

        // If the file is compressed, we have to go a different path
        if (dwFileAttributes & FILE_ATTRIBUTE_COMPRESSED ||
            //dwFileAttributes & FILE_ATTRIBUTE_ENCRYPTED  ||
            dwFileAttributes & FILE_ATTRIBUTE_SPARSE_FILE) {
            // We need to determine where the compressed file is located physically on disk.
            if (secureDeleteCompressed(pszFilePath, dwNumPasses)) {
                return true;
            }
        }

        HANDLE hfSource = CreateFileW(pszFilePath, 0, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hfSource == INVALID_HANDLE_VALUE) {
            return false;
        }

        DWORD nFileSizeHigh = 0;
        DWORD nFileSizeLow = GetFileSize(hfSource, &nFileSizeHigh);

        if (nFileSizeLow == 0xFFFFFFFF && (GetLastError() != NO_ERROR)) {
            CloseHandle(hfSource);
            return false;
        }

        CloseHandle(hfSource);

        // Regular path, non-compressed/encrypted/sparse file or one of those
        // types of files with their data resident in an MFT record: perform a
        // simple secure delete.
        return doSecureDelete(pszFilePath, nFileSizeHigh, nFileSizeLow, dwNumPasses);
    }
    else {
        SetFileAttributesW(pszFilePath, FILE_ATTRIBUTE_NORMAL);
        return (DeleteFileW(pszFilePath) != 0);
    }

    return false;
}

bool SecureDelete::deleteDirectory(const wchar_t* pszDirectoryPath, DWORD dwNumPasses, bool breakWhenError) {
    if (!pszDirectoryPath)
        return false;

    bool bRet = true;
    const int kBufSize = MAX_PATH * 4;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    WCHAR szTemp[kBufSize] = { 0 };
    WIN32_FIND_DATAW wfd;

    StringCchCopyW(szTemp, kBufSize, pszDirectoryPath);
    PathAddBackslashW(szTemp);
    StringCchCatW(szTemp, kBufSize, L"*.*");

    hFind = FindFirstFileW(szTemp, &wfd);
    if (hFind == INVALID_HANDLE_VALUE) {
        return false;
    }

    do {
        if (lstrcmpiW(wfd.cFileName, L".") != 0 && lstrcmpiW(wfd.cFileName, L"..") != 0) {
            StringCchCopyW(szTemp, kBufSize, pszDirectoryPath);
            PathAddBackslashW(szTemp);
            StringCchCatW(szTemp, kBufSize, wfd.cFileName);

            if (wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                bRet = deleteDirectory(szTemp, dwNumPasses, breakWhenError);
            }
            else {
                bRet = deleteFile(szTemp, dwNumPasses);
            }

            if (!bRet && breakWhenError)
                break;
        }
    } while (FindNextFileW(hFind, &wfd));

    FindClose(hFind);

    if (!bRet) {
        return bRet;
    }

    bRet = (RemoveDirectoryW(pszDirectoryPath) == TRUE);
    if (!bRet) {
        DWORD dwAttr = GetFileAttributesW(pszDirectoryPath);
        dwAttr &= ~(FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
        SetFileAttributesW(pszDirectoryPath, dwAttr);
        bRet = (RemoveDirectoryW(pszDirectoryPath) == TRUE);
    }

    return bRet;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Securely deletes a file's original name by renaming it several times.
// This works by changing each non-'.' character in the file's
// name to successive alphabetic characters, thus overwriting the name 26 times.
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
bool SecureDelete::overwriteFileName(const wchar_t* pszFileName, wchar_t* pszLastFileName) {
    wchar_t szNewName[MAX_PATH] = { 0 };
    wchar_t* pLastSlash = NULL;
    size_t i = 0, j = 0, index = 0;

    wcscpy(pszLastFileName, pszFileName);
    pLastSlash = wcsrchr(pszLastFileName, L'\\');
    index = (pLastSlash - pszLastFileName) / sizeof(char);

    // Loop through each letter in the English alphabet
    wcscpy(szNewName, pszFileName);
    for (i = 0; i < 26; i++) {
        // Replace each non-'.' character with the same letter
        for (j = index + 1; j < wcslen(pszFileName); j++) {
            if (pszFileName[j] != L'.') {
                szNewName[j] = (TCHAR)i + L'A';
            }
        }

        // Got a new name, so rename file
        if (!MoveFileW(pszLastFileName, szNewName)) {
            // Bail on error
            return false;
        }

        wcscpy(pszLastFileName, szNewName);
    }

    return true;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// This function implements a secure santize of rigid (removable and fixed) disk media as per
// the Department of Defense clearing and sanitizing standard: DOD 5220.22-M
//
// The standard states that hard disk media is sanatized by
// overwriting with a character, then the character's complement,
// and then a random character. Note that the standard specicically
// states that this method is not suitable for TOP SECRET information.
// TOP SECRET data sanatizing is only achievable by a Type 1 or 2
// degauss of the disk, or by disintegrating, incinerating,
// pulverizing, shreding, or melting the disk.
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
bool SecureDelete::overwriteFile(HANDLE hFileHandle, unsigned __int64 Length, DWORD dwNumPasses) {
    ULONGLONG totalWritten = 0LL;
    ULONG bytesWritten = 0L, bytesToWrite = 0L;
    LARGE_INTEGER seekLength;

    if (hFileHandle == INVALID_HANDLE_VALUE)
        return false;

    if (!fillBuffer_)
        return false;

    // Do the overwrite
    for (DWORD passes = 0; passes < dwNumPasses; passes++) {
        // Move back to the start of where we're overwriting
        if (passes != 0) {
            seekLength.QuadPart = 0LL;
            seekLength.QuadPart = -(LONGLONG)Length;
            SetFilePointer(hFileHandle, seekLength.LowPart, &seekLength.HighPart, FILE_CURRENT);
        }

        // Loop and overwrite
        totalWritten = 0;
        while (totalWritten < Length) {
            if (Length - totalWritten > 1024 * 1024) {
                bytesToWrite = 1024 * 1024;
            }
            else {
                bytesToWrite = (ULONG)(Length - totalWritten);
            }

            if (bytesToWrite > CLEANBUFSIZE) {
                bytesToWrite = CLEANBUFSIZE;
            }

            if (!WriteFile(hFileHandle, fillBuffer_, bytesToWrite, &bytesWritten, NULL)) {
                return false;
            }

            // Note: no need to flush since the file is opened with write-through or
            // no cache buffering

            totalWritten += bytesWritten;
        }
    }
    return true;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Performs a secure delete on the specified file.
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
bool SecureDelete::doSecureDelete(const wchar_t* pszFilePath, long FileLengthHi, unsigned long FileLengthLo, DWORD dwNumPasses) {
    HANDLE hFile = INVALID_HANDLE_VALUE;
    ULONGLONG bytesToWrite = 0LL, bytesWritten = 0LL;
    ULARGE_INTEGER fileLength;
    wchar_t szLastFileName[MAX_PATH] = { 0 };

    hFile = CreateFileW(pszFilePath,
        GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_WRITE_THROUGH,
        NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        return false;
    }

    if (FileLengthLo || FileLengthHi) {
        SetFilePointer(hFile, 0, NULL, FILE_BEGIN);

        fileLength.LowPart = FileLengthLo;
        fileLength.HighPart = FileLengthHi;

        bytesWritten = 0;

        while (bytesWritten < fileLength.QuadPart) {
            bytesToWrite = min(fileLength.QuadPart - bytesWritten, 65536);
            if (!overwriteFile(hFile, (DWORD)bytesToWrite, dwNumPasses)) {
                CloseHandle(hFile);
                return false;
            }
            bytesWritten += bytesToWrite;
        }
    }

    CloseHandle(hFile);

    // Rename the file a few times
    overwriteFileName(pszFilePath, szLastFileName);

    // Now we can delete the file
    if (!DeleteFileW(szLastFileName)) {
        // Rename back to original name so as not to confuse the user
        if (!MoveFileW(szLastFileName, pszFilePath)) {
        }
        return false;
    }

    return true;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// This is only invoked for compressed, encrypted or sparse files,
// which exists only on NTFS drives (WinNT/2K). Thus, we can use
// the defrag API to zap the clusters belonging to the file
// Determines if the the file is non-resident (outside the MFT), and
// if so and we were able to open the volume for write access, we zap
// the clusters.
//
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
bool SecureDelete::scanFile(HANDLE hVolumeHandle, DWORD dwClusterSize, HANDLE hFileHandle, bool* pReallyCompressed, bool* pZappedFile, DWORD dwNumPasses) {
    DWORD status;
    int i = 0;
    IO_STATUS_BLOCK ioStatus;
    ULONGLONG startVcn, prevVcn;
    LARGE_INTEGER clusterOffset;
    ULONGLONG endOfPrevRun;
    PGET_RETRIEVAL_DESCRIPTOR fileMappings;
    ULONGLONG* pFileMap = NULL;
    int lines = 0;

    pFileMap = (ULONGLONG*)malloc(FILEMAPSIZE * sizeof(ULONGLONG));
    if (!pFileMap) {
        return false;
    }

    //
    // Assume file is in an MFT record.
    //
    if (pReallyCompressed)
        *pReallyCompressed = false;

    if (pZappedFile)
        *pZappedFile = false;

    startVcn = 0;
    endOfPrevRun = LLINVALID;
    fileMappings = (PGET_RETRIEVAL_DESCRIPTOR)pFileMap;
    while (!(status = NtFsControlFile(hFileHandle, NULL, NULL, 0, &ioStatus,
        FSCTL_GET_RETRIEVAL_POINTERS,
        &startVcn, sizeof(startVcn),
        fileMappings, FILEMAPSIZE * sizeof(ULONGLONG))) ||
        status == STATUS_BUFFER_OVERFLOW ||
        status == STATUS_PENDING) {
        // If the operation is pending, wait for it to finish
        if (status == STATUS_PENDING) {
            WaitForSingleObject(hFileHandle, INFINITE);

            // Get the status from the status block
            if (ioStatus.Status != STATUS_SUCCESS && ioStatus.Status != STATUS_BUFFER_OVERFLOW) {
                free(pFileMap);
                pFileMap = NULL;
                return ioStatus.Status == STATUS_SUCCESS;
            }
        }

        // Loop through the buffer of number/cluster pairs, printing them out.
        startVcn = fileMappings->StartVcn;
        prevVcn = fileMappings->StartVcn;
        for (i = 0; i < (ULONGLONG)fileMappings->NumberOfPairs; i++) {
            // On NT 4.0, a compressed virtual run (0-filled) is identified with a cluster offset of -1
            if (fileMappings->Pair[i].Lcn != LLINVALID) {
                // Its compressed and outside the zone
                if (pReallyCompressed)
                    *pReallyCompressed = true;

                // Overwrite the clusters if we were able to open the volume for write access.
                if (hVolumeHandle != INVALID_HANDLE_VALUE) {
                    clusterOffset.QuadPart = fileMappings->Pair[i].Lcn * dwClusterSize;
                    SetFilePointer(hVolumeHandle, clusterOffset.LowPart, &clusterOffset.HighPart, FILE_BEGIN);
                    if (!overwriteFile(hVolumeHandle, dwClusterSize * (DWORD)(fileMappings->Pair[i].Vcn - startVcn), dwNumPasses)) {
                        free(pFileMap);
                        pFileMap = NULL;
                        // Couldn't zap the clusters, so we'll have to clean the free space
                        return true;
                    }
                }
                else {
                    free(pFileMap);
                    pFileMap = NULL;
                    return true;
                }
            }
            startVcn = fileMappings->Pair[i].Vcn;
        }

        // If the buffer wasn't overflowed, then we're done
        if (!status) {
            break;
        }
    }

    free(pFileMap);
    pFileMap = NULL;
    // Return now if there were any errors
    if (status && status != STATUS_INVALID_PARAMETER) {
    }

    // If we made through with no errors we've overwritten all the file's clusters.
    if (status == STATUS_SUCCESS) {
        if (pZappedFile)
            *pZappedFile = true;
    }

    return status == STATUS_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// More complicated than a regular file - we actually try to use
// direct disk access to overwrite the clusters that are used by a
// compressed file. The function returns false if the file is
// not really compressed (it is stored as resident data in the MFT).
//
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
bool SecureDelete::secureDeleteCompressed(const wchar_t* sFileName, DWORD dwNumPasses) {
    HANDLE hFile = INVALID_HANDLE_VALUE;
    bool nReallyCompressed = false;
    bool bZappedFile = false;
    wchar_t sLastFileName[MAX_PATH];
    static wchar_t volumeName[] = L"\\\\.\\A:";
    static wchar_t volumeRoot[] = L"A:\\";
    static HANDLE hVolume = INVALID_HANDLE_VALUE;
    static DWORD clusterSize;
    DWORD sectorsPerCluster = 0, bytesPerSector = 0, freeClusters = 0, totalClusters = 0;

    // If we haven't opened the volume, attempt it now
    if (hVolume == INVALID_HANDLE_VALUE) {
        volumeName[4] = sFileName[0];
        hVolume = CreateFileW(volumeName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, 0);

        volumeRoot[0] = sFileName[0];
        GetDiskFreeSpace(volumeRoot, &sectorsPerCluster, &bytesPerSector, &freeClusters, &totalClusters);

        clusterSize = bytesPerSector * sectorsPerCluster;
    }

    // Open the file exclusively
    hFile = CreateFileW(sFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return true;
    }

    // Scan the location of the file
    if (!scanFile(hVolume, clusterSize, hFile, &nReallyCompressed, &bZappedFile, dwNumPasses)) {
        CloseHandle(hFile);
        return true;
    }

    // Done with the file handle
    CloseHandle(hFile);

    // If the file is really compressed (it is non-resident), we can delete it now.
    if (nReallyCompressed) {
        // Rename the file a few times
        overwriteFileName(sFileName, sLastFileName);

        if (!DeleteFileW(sLastFileName)) {
            // Rename back to the original name on error so as not to confuse the user.
            if (!MoveFileW(sLastFileName, sFileName)) {
            }
            return true;
        }
    }

    // Return true if the file had clusters outside the MFT
    return nReallyCompressed;
}
