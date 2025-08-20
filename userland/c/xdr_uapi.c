//
// XDR Userland API - C Helper Functions
// Provides C functions to verify ABI compatibility and helper utilities
//

#include "../shared/xdr_shared.h"
#include <windows.h>

//
// Get ABI version for compatibility checking
//
__declspec(dllexport) uint32_t xdr_abi_version(void)
{
    return XDR_ABI_VERSION;
}

//
// Get compile-time constants for Rust
//
__declspec(dllexport) uint32_t xdr_shm_default_size(void)
{
    return XDR_SHM_DEFAULT_SIZE;
}

__declspec(dllexport) uint32_t xdr_shm_magic(void)
{
    return XDR_SHM_MAGIC;
}

__declspec(dllexport) uint32_t xdr_max_path(void)
{
    return XDR_MAX_PATH;
}

__declspec(dllexport) uint32_t xdr_max_string(void)
{
    return XDR_MAX_STRING;
}

__declspec(dllexport) uint32_t xdr_event_record_size(void)
{
    return sizeof(XDR_EVENT_RECORD);
}

__declspec(dllexport) uint32_t xdr_shm_header_size(void)
{
    return sizeof(XDR_SHM_HEADER);
}

//
// IOCTL code getters for Rust (since CTL_CODE macro doesn't work well in bindgen)
//
__declspec(dllexport) uint32_t xdr_ioctl_get_version(void)
{
    return IOCTL_XDR_GET_VERSION;
}

__declspec(dllexport) uint32_t xdr_ioctl_map_shm(void)
{
    return IOCTL_XDR_MAP_SHM;
}

__declspec(dllexport) uint32_t xdr_ioctl_set_config(void)
{
    return IOCTL_XDR_SET_CONFIG;
}

__declspec(dllexport) uint32_t xdr_ioctl_peek_fallback(void)
{
    return IOCTL_XDR_PEEK_FALLBACK;
}

__declspec(dllexport) uint32_t xdr_ioctl_dequeue_fallback(void)
{
    return IOCTL_XDR_DEQUEUE_FALLBACK;
}

__declspec(dllexport) uint32_t xdr_ioctl_user_event(void)
{
    return IOCTL_XDR_USER_EVENT;
}

//
// Utility function to validate event record structure
//
__declspec(dllexport) int xdr_validate_event_record(const XDR_EVENT_RECORD* record)
{
    if (!record) {
        return 0;
    }

    // Check version
    if (record->header.version != XDR_ABI_VERSION) {
        return 0;
    }

    // Check source bounds
    if (record->header.source >= XDR_SOURCE_MAX) {
        return 0;
    }

    // Check severity bounds
    if (record->header.severity > XDR_SEVERITY_CRITICAL) {
        return 0;
    }

    // Check total size is reasonable
    if (record->total_size < sizeof(XDR_EVENT_HEADER) ||
        record->total_size > sizeof(XDR_EVENT_RECORD)) {
        return 0;
    }

    return 1; // Valid
}

//
// Helper to compute FNV-1a hash (for key generation)
//
__declspec(dllexport) uint64_t xdr_fnv1a_hash(const void* data, size_t length)
{
    const uint8_t* bytes = (const uint8_t*)data;
    uint64_t hash = 0xCBF29CE484222325ULL; // FNV offset basis
    size_t i;

    if (!data || length == 0) {
        return 0;
    }

    for (i = 0; i < length; i++) {
        hash ^= bytes[i];
        hash *= 0x100000001B3ULL; // FNV prime
    }

    return hash;
}

//
// Helper to get current timestamp in Windows FILETIME format
//
__declspec(dllexport) uint64_t xdr_current_timestamp(void)
{
    FILETIME ft;
    ULARGE_INTEGER uli;

    GetSystemTimeAsFileTime(&ft);
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;

    return uli.QuadPart;
}

//
// Helper to convert FILETIME to Unix timestamp
//
__declspec(dllexport) uint64_t xdr_filetime_to_unix(uint64_t filetime)
{
    // FILETIME is 100ns intervals since January 1, 1601
    // Unix timestamp is seconds since January 1, 1970
    // Difference is 11644473600 seconds
    const uint64_t EPOCH_DIFFERENCE = 11644473600ULL;
    
    if (filetime == 0) {
        return 0;
    }

    // Convert 100ns intervals to seconds and adjust epoch
    return (filetime / 10000000ULL) - EPOCH_DIFFERENCE;
}

//
// Helper to get process information
//
__declspec(dllexport) int xdr_get_process_info(uint32_t pid, 
                                              wchar_t* image_path, 
                                              size_t image_path_size,
                                              uint32_t* session_id)
{
    HANDLE hProcess;
    DWORD size;
    WCHAR path[MAX_PATH];

    if (!image_path || image_path_size == 0) {
        return 0;
    }

    // Initialize outputs
    image_path[0] = L'\0';
    if (session_id) {
        *session_id = 0;
    }

    // Open process
    hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) {
        return 0;
    }

    // Get image path
    size = MAX_PATH;
    if (QueryFullProcessImageNameW(hProcess, 0, path, &size)) {
        wcsncpy_s(image_path, image_path_size, path, _TRUNCATE);
    }

    // Get session ID
    if (session_id) {
        ProcessIdToSessionId(pid, session_id);
    }

    CloseHandle(hProcess);
    return 1;
}

//
// Helper to check if running as administrator
//
__declspec(dllexport) int xdr_is_admin(void)
{
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;

    // Create SID for administrators group
    if (AllocateAndInitializeSid(&NtAuthority, 2,
                                SECURITY_BUILTIN_DOMAIN_RID,
                                DOMAIN_ALIAS_RID_ADMINS,
                                0, 0, 0, 0, 0, 0,
                                &adminGroup)) {
        // Check if current user is member of administrators group
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }

    return isAdmin ? 1 : 0;
}

//
// Helper to enable debug privilege
//
__declspec(dllexport) int xdr_enable_debug_privilege(void)
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), 
                         TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, 
                         &hToken)) {
        return 0;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return 0;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        CloseHandle(hToken);
        return 0;
    }

    CloseHandle(hToken);
    return (GetLastError() == ERROR_SUCCESS) ? 1 : 0;
}