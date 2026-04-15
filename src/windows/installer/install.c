// Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
// SPDX-License-Identifier: BSD-3-Clause

// Qualcomm USB Userspace Driver Installer
// Self-extracting EXE: a ZIP payload containing INF+CAT files is appended
// at build time. At runtime the payload is extracted to a temp directory,
// drivers are installed via pnputil, and the temp directory is cleaned up.
// Must be run as Administrator.
//
// Usage:
//   QcomUsbDriverInstaller.exe                 Install (auto-upgrades old version)
//   QcomUsbDriverInstaller.exe /query          Query installed version
//   QcomUsbDriverInstaller.exe /force          Force install (skip version check)
//   QcomUsbDriverInstaller.exe /version        Print installer version and exit
//   QcomUsbDriverInstaller.exe /help           Print usage

#include <windows.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <shlwapi.h>
#include <shellapi.h>

#include "miniz.h"
#include "version.h"

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")

// ============================================================================
// Payload trailer — appended after the ZIP at the end of the EXE
// ============================================================================

#pragma pack(push, 1)
typedef struct {
    char     magic[8];       // "QUSBPK01"
    uint64_t payloadOffset;  // Offset of ZIP data from start of file
    uint64_t payloadSize;    // Size of ZIP data in bytes
    uint32_t crc32;          // CRC32 of ZIP data
    uint32_t reserved;       // Reserved for future use
} PayloadTrailer;
#pragma pack(pop)

static const char kPayloadMagic[8] = { 'Q','U','S','B','P','K','0','1' };
#define TRAILER_SIZE sizeof(PayloadTrailer)

// ============================================================================
// Version comparison
// Parse version string "major.minor.patch.build" and compare.
// Returns: -1 if a < b, 0 if equal, 1 if a > b
// ============================================================================

typedef struct {
    int major, minor, patch, build;
} VersionInfo;

static bool ParseVersion(const char *str, VersionInfo *ver)
{
    memset(ver, 0, sizeof(*ver));
    if (!str || !*str) return false;
    int n = sscanf(str, "%d.%d.%d.%d",
                   &ver->major, &ver->minor, &ver->patch, &ver->build);
    return n >= 1;
}

static int CompareVersion(const VersionInfo *a, const VersionInfo *b)
{
    if (a->major != b->major) return a->major < b->major ? -1 : 1;
    if (a->minor != b->minor) return a->minor < b->minor ? -1 : 1;
    if (a->patch != b->patch) return a->patch < b->patch ? -1 : 1;
    if (a->build != b->build) return a->build < b->build ? -1 : 1;
    return 0;
}

// ============================================================================
// Registry helpers — track installed version
// ============================================================================

static bool RegReadString(HKEY hRoot, const char *subKey, const char *valueName,
                          char *buf, DWORD bufSize)
{
    HKEY hKey;
    if (RegOpenKeyExA(hRoot, subKey, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return false;

    DWORD type = 0, size = bufSize;
    LSTATUS status = RegQueryValueExA(hKey, valueName, NULL, &type,
                                      (LPBYTE)buf, &size);
    RegCloseKey(hKey);
    return status == ERROR_SUCCESS && type == REG_SZ;
}

static bool RegWriteString(HKEY hRoot, const char *subKey, const char *valueName,
                           const char *value)
{
    HKEY hKey;
    DWORD disposition;
    if (RegCreateKeyExA(hRoot, subKey, 0, NULL, REG_OPTION_NON_VOLATILE,
                        KEY_WRITE, NULL, &hKey, &disposition) != ERROR_SUCCESS)
        return false;

    LSTATUS status = RegSetValueExA(hKey, valueName, 0, REG_SZ,
                                    (const BYTE *)value,
                                    (DWORD)(strlen(value) + 1));
    RegCloseKey(hKey);
    return status == ERROR_SUCCESS;
}

static bool GetInstalledVersion(char *buf, DWORD bufSize)
{
    return RegReadString(HKEY_LOCAL_MACHINE, INSTALLER_REG_KEY,
                         INSTALLER_REG_VERSION, buf, bufSize);
}

static bool GetInstalledINFList(char *buf, DWORD bufSize)
{
    return RegReadString(HKEY_LOCAL_MACHINE, INSTALLER_REG_KEY,
                         INSTALLER_REG_INF_LIST, buf, bufSize);
}

static bool GetInstalledPackageName(char *buf, DWORD bufSize)
{
    return RegReadString(HKEY_LOCAL_MACHINE, INSTALLER_REG_KEY,
                         INSTALLER_REG_PACKAGE, buf, bufSize);
}

static bool GetInstallDate(char *buf, DWORD bufSize)
{
    return RegReadString(HKEY_LOCAL_MACHINE, INSTALLER_REG_KEY,
                         INSTALLER_REG_INSTALL_DATE, buf, bufSize);
}

static void SaveInstallInfo(const char *version, const char *infList)
{
    RegWriteString(HKEY_LOCAL_MACHINE, INSTALLER_REG_KEY,
                   INSTALLER_REG_VERSION, version);
    RegWriteString(HKEY_LOCAL_MACHINE, INSTALLER_REG_KEY,
                   INSTALLER_REG_PACKAGE, INSTALLER_PACKAGE_NAME);
    RegWriteString(HKEY_LOCAL_MACHINE, INSTALLER_REG_KEY,
                   INSTALLER_REG_INF_LIST, infList);

    // Save install date
    SYSTEMTIME st;
    char dateBuf[64];
    GetLocalTime(&st);
    snprintf(dateBuf, sizeof(dateBuf), "%04d-%02d-%02d %02d:%02d:%02d",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    RegWriteString(HKEY_LOCAL_MACHINE, INSTALLER_REG_KEY,
                   INSTALLER_REG_INSTALL_DATE, dateBuf);
}

// ============================================================================
// Admin check / elevation
// ============================================================================

static bool IsRunningAsAdmin(void)
{
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    PSID adminGroup = NULL;

    if (AllocateAndInitializeSid(&ntAuthority, 2,
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin != FALSE;
}

static bool RelaunchAsAdmin(int argc, char *argv[])
{
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);

    // Rebuild argument string (skip argv[0])
    char args[2048] = {0};
    for (int i = 1; i < argc; i++) {
        if (i > 1) strcat_s(args, sizeof(args), " ");
        strcat_s(args, sizeof(args), argv[i]);
    }

    SHELLEXECUTEINFOA sei = {0};
    sei.cbSize = sizeof(sei);
    sei.lpVerb = "runas";
    sei.lpFile = exePath;
    sei.lpParameters = args[0] ? args : NULL;
    sei.nShow = SW_SHOWNORMAL;
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;

    if (!ShellExecuteExA(&sei))
        return false;

    if (sei.hProcess) {
        WaitForSingleObject(sei.hProcess, INFINITE);
        CloseHandle(sei.hProcess);
    }
    return true;
}

// ============================================================================
// Payload extraction
// ============================================================================

static bool ReadTrailer(const char *exePath, PayloadTrailer *trailer)
{
    HANDLE hFile = CreateFileA(exePath, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return false;

    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize) ||
        fileSize.QuadPart < (LONGLONG)TRAILER_SIZE) {
        CloseHandle(hFile);
        return false;
    }

    LARGE_INTEGER seekPos;
    seekPos.QuadPart = fileSize.QuadPart - (LONGLONG)TRAILER_SIZE;
    if (!SetFilePointerEx(hFile, seekPos, NULL, FILE_BEGIN)) {
        CloseHandle(hFile);
        return false;
    }

    DWORD bytesRead = 0;
    if (!ReadFile(hFile, trailer, (DWORD)TRAILER_SIZE, &bytesRead, NULL) ||
        bytesRead != TRAILER_SIZE) {
        CloseHandle(hFile);
        return false;
    }

    CloseHandle(hFile);
    return memcmp(trailer->magic, kPayloadMagic, 8) == 0;
}

static bool ExtractPayload(const char *exePath, const char *extractDir,
                           PayloadTrailer *trailer)
{
    HANDLE hFile = CreateFileA(exePath, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return false;

    LARGE_INTEGER seekPos;
    seekPos.QuadPart = (LONGLONG)trailer->payloadOffset;
    if (!SetFilePointerEx(hFile, seekPos, NULL, FILE_BEGIN)) {
        CloseHandle(hFile);
        return false;
    }

    // Read ZIP data into memory
    size_t zipSize = (size_t)trailer->payloadSize;
    unsigned char *zipData = (unsigned char *)malloc(zipSize);
    if (!zipData) {
        CloseHandle(hFile);
        return false;
    }

    DWORD totalRead = 0;
    while (totalRead < (DWORD)zipSize) {
        DWORD toRead = (DWORD)min(zipSize - totalRead, 1024 * 1024);
        DWORD bytesRead = 0;
        if (!ReadFile(hFile, zipData + totalRead, toRead, &bytesRead, NULL) ||
            bytesRead == 0) {
            free(zipData);
            CloseHandle(hFile);
            return false;
        }
        totalRead += bytesRead;
    }
    CloseHandle(hFile);

    // Validate CRC
    uint32_t crc = (uint32_t)mz_crc32(MZ_CRC32_INIT, zipData, zipSize);
    if (crc != trailer->crc32) {
        printf("ERROR: Payload CRC mismatch (expected 0x%08X, got 0x%08X)\n",
               trailer->crc32, crc);
        free(zipData);
        return false;
    }

    // Extract using miniz
    mz_zip_archive zip = {0};
    if (!mz_zip_reader_init_mem(&zip, zipData, zipSize, 0)) {
        printf("ERROR: Failed to open embedded ZIP archive\n");
        free(zipData);
        return false;
    }

    mz_uint numFiles = mz_zip_reader_get_num_files(&zip);
    bool success = true;

    for (mz_uint i = 0; i < numFiles; i++) {
        mz_zip_archive_file_stat fileStat;
        if (!mz_zip_reader_file_stat(&zip, i, &fileStat)) {
            success = false;
            break;
        }

        char fullPath[MAX_PATH];
        snprintf(fullPath, MAX_PATH, "%s\\%s", extractDir, fileStat.m_filename);

        // Convert forward slashes
        for (char *p = fullPath; *p; p++) {
            if (*p == '/') *p = '\\';
        }

        if (mz_zip_reader_is_file_a_directory(&zip, i)) {
            CreateDirectoryA(fullPath, NULL);
        } else {
            // Ensure parent directory exists
            char parentDir[MAX_PATH];
            strncpy_s(parentDir, MAX_PATH, fullPath, _TRUNCATE);
            PathRemoveFileSpecA(parentDir);
            CreateDirectoryA(parentDir, NULL);

            // Extract to memory and write using Win32 API
            size_t uncompSize = 0;
            void *data = mz_zip_reader_extract_to_heap(&zip, i, &uncompSize, 0);
            if (data) {
                HANDLE hOut = CreateFileA(fullPath, GENERIC_WRITE, 0,
                    NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                if (hOut != INVALID_HANDLE_VALUE) {
                    DWORD written = 0;
                    WriteFile(hOut, data, (DWORD)uncompSize, &written, NULL);
                    CloseHandle(hOut);
                } else {
                    printf("ERROR: Failed to write %s (error %lu)\n",
                           fileStat.m_filename, GetLastError());
                    success = false;
                }
                mz_free(data);
            } else {
                printf("ERROR: Failed to extract %s\n", fileStat.m_filename);
                success = false;
            }
        }

        if (!success) break;
    }

    mz_zip_reader_end(&zip);
    free(zipData);
    return success;
}

// ============================================================================
// Driver uninstall / install via pnputil
// ============================================================================

static int UninstallDriverByINF(const char *infName)
{
    // Use pnputil /enum-drivers to find the OEM name for this INF,
    // then /delete-driver to remove it.
    char cmdLine[512];
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    DWORD exitCode = 1;
    char tempFile[MAX_PATH];
    char tempDir[MAX_PATH];

    // Write pnputil output to a temp file so we can parse it
    GetTempPathA(MAX_PATH, tempDir);
    snprintf(tempFile, MAX_PATH, "%spnputil_enum_%lu.txt",
             tempDir, GetCurrentProcessId());

    snprintf(cmdLine, sizeof(cmdLine),
             "cmd /c pnputil /enum-drivers > \"%s\" 2>&1", tempFile);

    si.cb = sizeof(si);
    if (!CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        return 1;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    // Parse the output to find the OEM INF name for our original INF
    FILE *fp = fopen(tempFile, "r");
    if (!fp) {
        DeleteFileA(tempFile);
        return 1;
    }

    char line[512];
    char currentOem[128] = {0};
    bool found = false;

    while (fgets(line, sizeof(line), fp)) {
        // Look for "Published Name:" lines
        char *p = strstr(line, "Published Name");
        if (!p) p = strstr(line, "Published name");
        if (p) {
            char *colon = strchr(p, ':');
            if (colon) {
                colon++;
                while (*colon == ' ') colon++;
                // Trim newline
                char *nl = strchr(colon, '\n');
                if (nl) *nl = '\0';
                nl = strchr(colon, '\r');
                if (nl) *nl = '\0';
                strncpy_s(currentOem, sizeof(currentOem), colon, _TRUNCATE);
            }
        }

        // Look for "Original Name:" lines
        p = strstr(line, "Original Name");
        if (!p) p = strstr(line, "Original name");
        if (p) {
            char *colon = strchr(p, ':');
            if (colon) {
                colon++;
                while (*colon == ' ') colon++;
                char *nl = strchr(colon, '\n');
                if (nl) *nl = '\0';
                nl = strchr(colon, '\r');
                if (nl) *nl = '\0';

                if (_stricmp(colon, infName) == 0 && currentOem[0]) {
                    found = true;
                    break;
                }
            }
        }
    }
    fclose(fp);
    DeleteFileA(tempFile);

    if (!found || !currentOem[0]) {
        // Driver not in the store — nothing to uninstall
        return 0;
    }

    printf("  Removing old driver: %s (OEM: %s)\n", infName, currentOem);

    snprintf(cmdLine, sizeof(cmdLine),
             "pnputil /delete-driver %s /uninstall /force", currentOem);

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));

    if (!CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        printf("  WARNING: Failed to launch pnputil for uninstall\n");
        return 1;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (exitCode == 0) {
        printf("  OK: %s uninstalled\n", infName);
    } else {
        printf("  WARNING: %s uninstall returned code %lu (may already be removed)\n",
               infName, exitCode);
    }
    return 0;  // Non-fatal: proceed with install even if uninstall failed
}

static int InstallDriver(const char *infPath, const char *infName)
{
    char cmdLine[MAX_PATH + 64];
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    DWORD exitCode = 1;

    si.cb = sizeof(si);
    snprintf(cmdLine, sizeof(cmdLine),
             "pnputil /add-driver \"%s\" /install", infPath);

    printf("  Installing: %s\n", infName);

    if (!CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        printf("  ERROR: Failed to launch pnputil (error %lu)\n", GetLastError());
        return 1;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (exitCode == 0) {
        printf("  OK: %s installed successfully\n", infName);
    } else {
        printf("  FAILED: %s (pnputil exit code %lu)\n", infName, exitCode);
    }
    return (int)exitCode;
}

// ============================================================================
// Uninstall all previously installed INFs (from registry list)
// ============================================================================

static void UninstallOldDrivers(void)
{
    char infList[4096] = {0};
    if (!GetInstalledINFList(infList, sizeof(infList))) {
        printf("No previously installed driver list found.\n\n");
        return;
    }

    printf("Uninstalling previous driver packages...\n\n");

    // INF list is semicolon-separated: "qcadb.inf;qcserlib.inf;..."
    char *ctx = NULL;
    char *token = strtok_s(infList, ";", &ctx);
    while (token) {
        // Trim whitespace
        while (*token == ' ') token++;
        if (*token) {
            UninstallDriverByINF(token);
        }
        token = strtok_s(NULL, ";", &ctx);
    }
    printf("\n");
}

// ============================================================================
// Temp directory helpers
// ============================================================================

static bool CreateTempExtractDir(char *outPath, size_t outSize)
{
    char tempBase[MAX_PATH];
    DWORD len = GetTempPathA(MAX_PATH, tempBase);
    if (len == 0 || len >= MAX_PATH) return false;

    snprintf(outPath, outSize, "%sQcomUsbDrivers_%lu",
             tempBase, GetCurrentProcessId());
    return CreateDirectoryA(outPath, NULL) ||
           GetLastError() == ERROR_ALREADY_EXISTS;
}

static void DeleteDirectoryRecursive(const char *dir)
{
    WIN32_FIND_DATAA fd;
    char search[MAX_PATH];
    snprintf(search, MAX_PATH, "%s\\*", dir);
    HANDLE hFind = FindFirstFileA(search, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
            continue;

        char fullPath[MAX_PATH];
        snprintf(fullPath, MAX_PATH, "%s\\%s", dir, fd.cFileName);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            DeleteDirectoryRecursive(fullPath);
        } else {
            DeleteFileA(fullPath);
        }
    } while (FindNextFileA(hFind, &fd));

    FindClose(hFind);
    RemoveDirectoryA(dir);
}

// ============================================================================
// Command handlers
// ============================================================================

static void PrintUsage(void)
{
    printf("Usage: QcomUsbDriverInstaller [options]\n\n");
    printf("Options:\n");
    printf("  (no options)   Install drivers (auto-upgrades if older version found)\n");
    printf("  /query         Query installed driver package name and version\n");
    printf("  /force         Force install (bypass version check, reinstall/downgrade)\n");
    printf("  /version       Print installer version and exit\n");
    printf("  /help          Print this help message\n");
}

static int CmdQuery(void)
{
    char version[128] = {0};
    char packageName[256] = {0};
    char infList[4096] = {0};
    char installDate[128] = {0};

    bool hasVersion = GetInstalledVersion(version, sizeof(version));
    bool hasPackage = GetInstalledPackageName(packageName, sizeof(packageName));
    bool hasInfList = GetInstalledINFList(infList, sizeof(infList));
    bool hasDate    = GetInstallDate(installDate, sizeof(installDate));

    if (!hasVersion) {
        printf("No Qualcomm USB Userspace Drivers installation found.\n");
        return 1;
    }

    printf("Installed Driver Package:\n");
    printf("  Package:   %s\n", hasPackage ? packageName : "(unknown)");
    printf("  Version:   %s\n", version);
    if (hasDate)
        printf("  Installed: %s\n", installDate);
    if (hasInfList) {
        printf("  INF files: ");
        // Print semicolon list more readably
        for (const char *p = infList; *p; p++) {
            if (*p == ';')
                printf(", ");
            else
                putchar(*p);
        }
        printf("\n");
    }
    printf("\n  Registry:  HKLM\\%s\n", INSTALLER_REG_KEY);
    return 0;
}

static int CmdVersion(void)
{
    printf("%s Installer v%s\n", INSTALLER_PACKAGE_NAME, INSTALLER_VERSION_STR);
    return 0;
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char *argv[])
{
    char exePath[MAX_PATH];
    char extractDir[MAX_PATH];
    char searchPath[MAX_PATH];
    WIN32_FIND_DATAA findData;
    HANDLE hFind;
    int installed = 0, failed = 0, total = 0;
    bool forceInstall = false;
    bool queryMode = false;
    bool versionMode = false;

    // Parse command-line arguments
    for (int i = 1; i < argc; i++) {
        if (_stricmp(argv[i], "/query") == 0 || _stricmp(argv[i], "-query") == 0) {
            queryMode = true;
        } else if (_stricmp(argv[i], "/force") == 0 || _stricmp(argv[i], "-force") == 0) {
            forceInstall = true;
        } else if (_stricmp(argv[i], "/version") == 0 || _stricmp(argv[i], "-version") == 0) {
            versionMode = true;
        } else if (_stricmp(argv[i], "/help") == 0 || _stricmp(argv[i], "-help") == 0 ||
                   _stricmp(argv[i], "/?") == 0 || _stricmp(argv[i], "-h") == 0) {
            PrintUsage();
            return 0;
        } else {
            printf("Unknown option: %s\n\n", argv[i]);
            PrintUsage();
            return 1;
        }
    }

    // Handle /version (no admin required)
    if (versionMode)
        return CmdVersion();

    // Handle /query (no admin required)
    if (queryMode)
        return CmdQuery();

    // --- Installation flow ---
    printf("==========================================\n");
    printf(" %s\n", INSTALLER_PACKAGE_NAME);
    printf(" Installer v%s\n", INSTALLER_VERSION_STR);
    printf("==========================================\n\n");

    // Check for admin
    if (!IsRunningAsAdmin()) {
        printf("Administrator privileges required. Requesting elevation...\n");
        if (RelaunchAsAdmin(argc, argv))
            return 0;
        printf("ERROR: Failed to obtain administrator privileges.\n");
        printf("Please right-click the installer and select 'Run as administrator'.\n");
        printf("\nPress any key to exit...\n");
        getchar();
        return 1;
    }

    // Get path to this EXE
    GetModuleFileNameA(NULL, exePath, MAX_PATH);

    // Read payload trailer
    PayloadTrailer trailer;
    if (!ReadTrailer(exePath, &trailer)) {
        printf("ERROR: No embedded driver payload found.\n");
        printf("This installer must be packaged using package.bat first.\n");
        printf("\nPress any key to exit...\n");
        getchar();
        return 1;
    }

    printf("Payload found: %llu bytes at offset %llu\n\n",
           (unsigned long long)trailer.payloadSize,
           (unsigned long long)trailer.payloadOffset);

    // Version check
    char installedVer[128] = {0};
    if (GetInstalledVersion(installedVer, sizeof(installedVer))) {
        VersionInfo viInstalled, viNew;
        ParseVersion(installedVer, &viInstalled);
        ParseVersion(INSTALLER_VERSION_STR, &viNew);
        int cmp = CompareVersion(&viNew, &viInstalled);

        printf("Currently installed version: %s\n", installedVer);
        printf("Installer version:           %s\n\n", INSTALLER_VERSION_STR);

        if (cmp == 0 && !forceInstall) {
            printf("Same version is already installed.\n");
            printf("Use /force to reinstall.\n");
            printf("\nPress any key to exit...\n");
            getchar();
            return 0;
        } else if (cmp < 0 && !forceInstall) {
            printf("A newer version (%s) is already installed.\n", installedVer);
            printf("Use /force to downgrade to %s.\n", INSTALLER_VERSION_STR);
            printf("\nPress any key to exit...\n");
            getchar();
            return 0;
        }

        if (cmp > 0) {
            printf("Upgrading from %s to %s...\n\n", installedVer,
                   INSTALLER_VERSION_STR);
        } else if (cmp < 0) {
            printf("FORCE: Downgrading from %s to %s...\n\n", installedVer,
                   INSTALLER_VERSION_STR);
        } else {
            printf("FORCE: Reinstalling version %s...\n\n", INSTALLER_VERSION_STR);
        }

        // Uninstall old drivers before installing new ones
        UninstallOldDrivers();
    } else {
        printf("No previous installation found. Performing fresh install.\n\n");
    }

    // Create temp extraction directory
    if (!CreateTempExtractDir(extractDir, sizeof(extractDir))) {
        printf("ERROR: Failed to create temp directory\n");
        printf("\nPress any key to exit...\n");
        getchar();
        return 1;
    }

    printf("Extracting to: %s\n\n", extractDir);

    // Extract embedded ZIP payload
    if (!ExtractPayload(exePath, extractDir, &trailer)) {
        printf("ERROR: Failed to extract driver payload\n");
        DeleteDirectoryRecursive(extractDir);
        printf("\nPress any key to exit...\n");
        getchar();
        return 1;
    }

    printf("Extraction complete. Installing drivers...\n\n");

    // Find and install all INF files in the extracted directory
    // Also build a list for registry
    char infListBuf[4096] = {0};
    size_t infListLen = 0;

    snprintf(searchPath, MAX_PATH, "%s\\*.inf", extractDir);
    hFind = FindFirstFileA(searchPath, &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        printf("ERROR: No .inf files found in extracted payload\n");
        DeleteDirectoryRecursive(extractDir);
        printf("\nPress any key to exit...\n");
        getchar();
        return 1;
    }

    do {
        char infPath[MAX_PATH];
        total++;
        printf("------------------\n");
        snprintf(infPath, MAX_PATH, "%s\\%s", extractDir, findData.cFileName);

        if (InstallDriver(infPath, findData.cFileName) == 0) {
            installed++;
        } else {
            failed++;
        }

        // Append to INF list (semicolon-separated)
        if (infListLen > 0 && infListLen < sizeof(infListBuf) - 1) {
            infListBuf[infListLen++] = ';';
        }
        size_t nameLen = strlen(findData.cFileName);
        if (infListLen + nameLen < sizeof(infListBuf)) {
            memcpy(infListBuf + infListLen, findData.cFileName, nameLen);
            infListLen += nameLen;
            infListBuf[infListLen] = '\0';
        }

        printf("\n");
    } while (FindNextFileA(hFind, &findData));

    FindClose(hFind);

    // Save installed version and INF list to registry
    if (installed > 0) {
        SaveInstallInfo(INSTALLER_VERSION_STR, infListBuf);
        printf("Version %s recorded in registry.\n\n", INSTALLER_VERSION_STR);
    }

    // Cleanup temp directory
    printf("Cleaning up temporary files...\n\n");
    DeleteDirectoryRecursive(extractDir);

    printf("==========================================\n");
    printf(" Installation Summary\n");
    printf("==========================================\n");
    printf("  Version:   %s\n", INSTALLER_VERSION_STR);
    printf("  Total:     %d\n", total);
    printf("  Installed: %d\n", installed);
    printf("  Failed:    %d\n", failed);
    printf("==========================================\n");

    printf("\nPress any key to exit...\n");
    getchar();
    return failed > 0 ? 1 : 0;
}