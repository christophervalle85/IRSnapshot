"""Lazy, narrow Win32 access. DLLs load only from the Windows system directory."""
import ctypes
from ctypes import wintypes
import platform
from uuid import UUID


KNOWN_FOLDERS = {
    'profile': '5e6c858f-0e22-4760-9afe-ea3317b67173',
    'appdata': '3eb685db-65f9-4cf6-a03a-e3ef65729f3d',
    'local_appdata': 'f1b32785-6fba-4fcf-9d55-7b8e7f157091',
    'startup': 'b97d20bb-f46a-4c97-ba10-5e3608430854',
    'common_startup': '82a5ea35-d9cd-47c5-9629-e15d2f714e6e',
}


class NativeWindows:
    """Construction is inert, including on non-Windows hosts."""
    def _dll(self, name):
        return ctypes.WinDLL(name, use_last_error=True, winmode=0x00000800)

    def _function(self, dll, name, args, result):
        function = getattr(self._dll(dll), name)
        function.argtypes, function.restype = args, result
        return function

    def _directory(self, function):
        call = self._function('kernel32.dll', function,
                              [wintypes.LPWSTR, wintypes.UINT], wintypes.UINT)
        size = 32768
        buffer = ctypes.create_unicode_buffer(size)
        count = call(buffer, size)
        if not count or count >= size:
            raise ctypes.WinError(ctypes.get_last_error())
        return buffer.value

    def system_directory(self):
        return self._directory('GetSystemDirectoryW')

    def windows_directory(self):
        return self._directory('GetWindowsDirectoryW')

    def architecture(self):
        class SystemInfo(ctypes.Structure):
            _fields_ = [('architecture', wintypes.WORD), ('reserved', wintypes.WORD),
                        ('page_size', wintypes.DWORD), ('minimum', ctypes.c_void_p),
                        ('maximum', ctypes.c_void_p), ('mask', ctypes.c_size_t),
                        ('processors', wintypes.DWORD), ('type', wintypes.DWORD),
                        ('granularity', wintypes.DWORD), ('level', wintypes.WORD),
                        ('revision', wintypes.WORD)]
        info = SystemInfo()
        call = self._function('kernel32.dll', 'GetNativeSystemInfo',
                              [ctypes.POINTER(SystemInfo)], None)
        call(ctypes.byref(info))
        return {9: 'AMD64', 0: 'x86', 12: 'ARM64'}.get(info.architecture, 'unknown')

    def hostname(self):
        call = self._function('kernel32.dll', 'GetComputerNameW',
                              [wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)], wintypes.BOOL)
        buffer, size = ctypes.create_unicode_buffer(256), wintypes.DWORD(256)
        if not call(buffer, ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        return buffer.value

    def windows_version(self):
        # sys.getwindowsversion (used by win32_ver) is independent of environment strings.
        release, version, service_pack, _ = platform.win32_ver()
        return ' '.join(value for value in (release, version, service_pack) if value)

    def _token_value(self, information_class, read):
        process = self._function('kernel32.dll', 'GetCurrentProcess', [], wintypes.HANDLE)()
        token = wintypes.HANDLE()
        open_token = self._function('advapi32.dll', 'OpenProcessToken',
                                   [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)], wintypes.BOOL)
        close = self._function('kernel32.dll', 'CloseHandle', [wintypes.HANDLE], wintypes.BOOL)
        if not open_token(process, 0x0008, ctypes.byref(token)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            get = self._function('advapi32.dll', 'GetTokenInformation',
                                [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                 ctypes.POINTER(wintypes.DWORD)], wintypes.BOOL)
            size = wintypes.DWORD()
            get(token, information_class, None, 0, ctypes.byref(size))
            if not size.value or size.value > 1048576:
                raise ctypes.WinError(ctypes.get_last_error())
            buffer = ctypes.create_string_buffer(size.value)
            if not get(token, information_class, buffer, size, ctypes.byref(size)):
                raise ctypes.WinError(ctypes.get_last_error())
            return read(buffer)
        finally:
            close(token)

    def collector_sid(self):
        def read(buffer):
            sid = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]
            result = wintypes.LPWSTR()
            convert = self._function('advapi32.dll', 'ConvertSidToStringSidW',
                                    [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)], wintypes.BOOL)
            free = self._function('kernel32.dll', 'LocalFree', [ctypes.c_void_p], ctypes.c_void_p)
            if not convert(sid, ctypes.byref(result)):
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                return result.value
            finally:
                free(ctypes.cast(result, ctypes.c_void_p))
        return self._token_value(1, read)

    def collector_username(self):
        def read(buffer):
            sid = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]
            lookup = self._function('advapi32.dll', 'LookupAccountSidW',
                [wintypes.LPCWSTR, ctypes.c_void_p, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD),
                 wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD)], wintypes.BOOL)
            name_len, domain_len, use = wintypes.DWORD(), wintypes.DWORD(), wintypes.DWORD()
            lookup(None, sid, None, ctypes.byref(name_len), None, ctypes.byref(domain_len), ctypes.byref(use))
            if not name_len.value or max(name_len.value, domain_len.value) > 32768:
                raise ctypes.WinError(ctypes.get_last_error())
            name = ctypes.create_unicode_buffer(name_len.value)
            domain = ctypes.create_unicode_buffer(max(1, domain_len.value))
            if not lookup(None, sid, name, ctypes.byref(name_len), domain, ctypes.byref(domain_len), ctypes.byref(use)):
                raise ctypes.WinError(ctypes.get_last_error())
            return domain.value + '\\' + name.value if domain.value else name.value
        return self._token_value(1, read)

    def elevated(self):
        return self._token_value(20, lambda buffer: bool(ctypes.cast(buffer, ctypes.POINTER(wintypes.DWORD))[0]))

    def known_folder(self, kind):
        class GUID(ctypes.Structure):
            _fields_ = [('data', ctypes.c_ubyte * 16)]
        guid = GUID.from_buffer_copy(UUID(KNOWN_FOLDERS[kind]).bytes_le)
        result = wintypes.LPWSTR()
        call = self._function('shell32.dll', 'SHGetKnownFolderPath',
            [ctypes.POINTER(GUID), wintypes.DWORD, wintypes.HANDLE, ctypes.POINTER(wintypes.LPWSTR)], ctypes.c_long)
        free = self._function('ole32.dll', 'CoTaskMemFree', [ctypes.c_void_p], None)
        # DONT_VERIFY avoids network/directory probes; no CREATE flag.
        status = call(ctypes.byref(guid), 0x00004000, None, ctypes.byref(result))
        try:
            if status < 0:
                raise OSError(status, 'Known-folder discovery failed')
            return result.value
        finally:
            if result:
                free(ctypes.cast(result, ctypes.c_void_p))

    def environment_value(self, name):
        call = self._function('kernel32.dll', 'GetEnvironmentVariableW',
            [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD], wintypes.DWORD)
        buffer = ctypes.create_unicode_buffer(32768)
        ctypes.set_last_error(0)
        count = call(name, buffer, len(buffer))
        if count >= len(buffer) or (not count and ctypes.get_last_error()):
            raise ctypes.WinError(ctypes.get_last_error())
        return buffer.value

    def drive_type(self, root):
        call = self._function('kernel32.dll', 'GetDriveTypeW', [wintypes.LPCWSTR], wintypes.UINT)
        return call(root)

    def registry(self):
        import winreg
        return winreg
