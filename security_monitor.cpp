#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <sstream>

using namespace std;

// Abstract base class for monitors
class Monitor {
    public:
        virtual bool checkEvent(const string& name) = 0;
        virtual const vector<string>& getMonitoredItems() const = 0;
        virtual ~Monitor() = default;
};

// FileMonitor Class - inherits from Monitor
class FileMonitor : public Monitor {
    private:
        vector<string> criticalFiles;

    public:
        FileMonitor() {
            criticalFiles = {
                "system32.dll",
                "config.sys",
                "kernel32.dll",
                "ntdll.dll",
                "boot.ini",
                "registry.dat",
                "autoexec.bat",
                "winlogon.exe",
                "explorer.exe",
                "services.exe",
                "svchost.exe"


            };
        }

        bool checkFileChange(const string& filename) {
            string lowerFilename = filename;
            transform(lowerFilename.begin(), lowerFilename.end(), lowerFilename.begin(), ::tolower);

            for (const auto& file : criticalFiles) {
                string lowerCritical = file;
                transform(lowerCritical.begin(), lowerCritical.end(), lowerCritical.begin(), ::tolower);
                if (lowerCritical == lowerFilename) {
                    return true;
                }
            }
            return false;
        }

        bool checkEvent(const string& name) override {
            return checkFileChange(name);
        }

        const vector<string>& getMonitoredItems() const override {
            return criticalFiles;
        }

        const vector<string>& getCriticalFiles() const {
            return criticalFiles;
        }
};

// ProcessMonitor Class - inherits from Monitor
class ProcessMonitor : public Monitor {
    private:
        vector<string> suspiciousProcesses;

    public:
        ProcessMonitor() {
            suspiciousProcesses = {
                "malware.exe",
                "keylogger.exe",
                "trojan.exe",
                "virus.exe",
                "backdoor.exe",
                "rootkit.exe",
                "spyware.exe",
                "ransomware.exe",
                "botnet.exe",
                "cryptominer.exe"
            };
        }

        bool checkProcessStart(const string& processName) {
            string lowerProcess = processName;
            transform(lowerProcess.begin(), lowerProcess.end(), lowerProcess.begin(), ::tolower);

            for (const auto& proc : suspiciousProcesses) {
                string lowerSuspicious = proc;
                transform(lowerSuspicious.begin(), lowerSuspicious.end(), lowerSuspicious.begin(), ::tolower);
                if (lowerSuspicious == lowerProcess) {
                    return true;
                }
            }
            return false;
        }

        bool checkEvent(const string& name) override {
            return checkProcessStart(name);
        }

        const vector<string>& getMonitoredItems() const override {
            return suspiciousProcesses;
        }

        const vector<string>& getSuspiciousProcesses() const {
            return suspiciousProcesses;
        }
};

// NetworkMonitor Class - inherits from Monitor
class NetworkMonitor : public Monitor {
    private:
        vector<string> blacklistedDomains;

    public:
        NetworkMonitor() {
            blacklistedDomains = {
                "malware.net",
                "hacker.org",
                "phishing.com",
                "botnet.ru",
                "trojan-host.xyz",
                "darkweb.onion",
                "exploit-kit.biz",
                "ransomware.site",
                "cryptojacking.io",
                "suspicious-ads.click"
            };
        }
        
        bool checkConnection(const string& domain) {
            string lowerDomain = domain;
            transform(lowerDomain.begin(), lowerDomain.end(), lowerDomain.begin(), ::tolower);

            for (const auto& blacklisted : blacklistedDomains) {
                string lowerBlacklisted = blacklisted;
                transform(lowerBlacklisted.begin(), lowerBlacklisted.end(), lowerBlacklisted.begin(), ::tolower);
                if (lowerBlacklisted == lowerDomain) {
                    return true;
                }
            }
            return false;
        }

        bool checkEvent(const string& name) override {
            return checkConnection(name);
        }

        const vector<string>& getMonitoredItems() const override {
            return blacklistedDomains;
        }

        const vector<string>& getBlacklistedDomains() const {
            return blacklistedDomains;
        }
};

// ThreatAnalyzer Class
class ThreatAnalyzer {
    private:
        FileMonitor& fileMonitor;
        ProcessMonitor& processMonitor;
        NetworkMonitor& networkMonitor;

        string getCurrentTimestamp() {
            auto now = chrono::system_clock::now();
            time_t time = chrono::system_clock::to_time_t(now);

            stringstream ss;
            ss << "[" << put_time(localtime(&time), "%Y-%m-%d %H:%M:%S") << "] ";
            return ss.str();
        }

    public:
        ThreatAnalyzer(FileMonitor& fm, ProcessMonitor& pm, NetworkMonitor& nm) 
            : fileMonitor(fm), processMonitor(pm), networkMonitor(nm) {}

        void analyzeFileChange(const string& filename) {
            string timestamp = getCurrentTimestamp();
            if (fileMonitor.checkFileChange(filename)) {
                cout << timestamp << "CRITICAL ALERT: Critical file modified -> " << filename << endl;
            } else {
                cout << timestamp << "SAFE: File not critical -> " << filename << endl;
            }
        }

        void analyzeProcessStart(const string& processName) {
            string timestamp = getCurrentTimestamp();
            if (processMonitor.checkProcessStart(processName)) {
                cout << timestamp << "WARNING: Suspicious process detected -> " << processName << endl;
            } else {
                cout << timestamp << "SAFE: Process " << processName << " is not suspicious" << endl;
            }
        }

        void analyzeNetworkConnection(const string& domain) {
            string timestamp = getCurrentTimestamp();
            if (networkMonitor.checkConnection(domain)) {
                cout << timestamp << "ALERT: Blacklisted connection detected -> " << domain << endl;
            } else {
                cout << timestamp << "SAFE: Domain " << domain << " is not blacklisted" << endl;
            }
        }

        void performFullSystemScan() {
            cout << "\nPERFORMING FULL SYSTEM SCAN...\n" << endl;
            string timestamp = getCurrentTimestamp();
            cout << timestamp << "Full system scan initiated" << endl;
            
            vector<string> testFiles = {"system32.dll", "readme.txt", "kernel32.dll", "document.pdf"};
            cout << "\nFile System Scan:" << endl;
            for (const auto& file : testFiles) {
                cout << "   ";
                analyzeFileChange(file);
            }

            cout << "\nProcess Scan:" << endl;
            vector<string> testProcesses = {"chrome.exe", "malware.exe", "notepad.exe", "keylogger.exe"};
            for (const auto& process : testProcesses) {
                cout << "   ";
                analyzeProcessStart(process);
            }

            cout << "\nNetwork Connection Scan:" << endl;
            vector<string> testDomains = {"google.com", "malware.net", "github.com", "hacker.org"};
            for (const auto& domain : testDomains) {
                cout << "   ";
                analyzeNetworkConnection(domain);
            }
            
            timestamp = getCurrentTimestamp();
            cout << "\n" << timestamp << "Full system scan completed!\n" << endl;
        }
};

// Simulator Class
class Simulator {
    private:
        FileMonitor fileMonitor;
        ProcessMonitor processMonitor;
        NetworkMonitor networkMonitor;
        ThreatAnalyzer threatAnalyzer;

    public:
        Simulator() : threatAnalyzer(fileMonitor, processMonitor, networkMonitor) {}

        void displayMenu() {
            cout << "\n" << string(50, '=') << endl;
            cout << "ENDPOINT SECURITY MONITOR - PHASE 1" << endl;
            cout << string(50, '=') << endl;
            cout << "1. Show monitored files" << endl;
            cout << "2. Show monitored processes" << endl;
            cout << "3. Show monitored network domains" << endl;
            cout << "4. Simulate file change" << endl;
            cout << "5. Simulate process start" << endl;
            cout << "6. Simulate network activity" << endl;
            cout << "7. Full system scan (iterate all)" << endl;
            cout << "8. Exit" << endl;
            cout << string(50, '=') << endl;
            cout << "Choose an option (1-8): ";
        }

        void showMonitoredFiles() {
            cout << "\nMONITORED CRITICAL FILES:" << endl;
            cout << string(40, '-') << endl;
            const auto& files = fileMonitor.getCriticalFiles();
            for (size_t i = 0; i < files.size(); ++i) {
                cout << setw(2) << (i + 1) << ". " << files[i] << endl;
            }
            cout << "\nTotal: " << files.size() << " critical files monitored\n" << endl;
        }

        void showMonitoredProcesses() {
            cout << "\nMONITORED SUSPICIOUS PROCESSES:" << endl;
            cout << string(40, '-') << endl;
            const auto& processes = processMonitor.getSuspiciousProcesses();
            for (size_t i = 0; i < processes.size(); ++i) {
                cout << setw(2) << (i + 1) << ". " << processes[i] << endl;
            }
            cout << "\nTotal: " << processes.size() << " suspicious processes monitored\n" << endl;
        }

        void showMonitoredDomains() {
            cout << "\nMONITORED BLACKLISTED DOMAINS:" << endl;
            cout << string(40, '-') << endl;
            const auto& domains = networkMonitor.getBlacklistedDomains();
            for (size_t i = 0; i < domains.size(); ++i) {
                cout << setw(2) << (i + 1) << ". " << domains[i] << endl;
            }
            cout << "\nTotal: " << domains.size() << " blacklisted domains monitored\n" << endl;
        }

        void simulateFileChange() {
            string filename;
            cout << "\nEnter filename to check: ";
            cin.ignore();
            getline(cin, filename);
            
            cout << "\nAnalyzing file: " << filename << endl;
            threatAnalyzer.analyzeFileChange(filename);
            cout << endl;
        }

        void simulateProcessStart() {
            string processName;
            cout << "\nEnter process name to check: ";
            cin.ignore();
            getline(cin, processName);
            
            cout << "\nAnalyzing process: " << processName << endl;
            threatAnalyzer.analyzeProcessStart(processName);
            cout << endl;
        }

        void simulateNetworkActivity() {
            string domain;
            cout << "\nEnter domain to check: ";
            cin.ignore();
            getline(cin, domain);
            
            cout << "\nAnalyzing network connection: " << domain << endl;
            threatAnalyzer.analyzeNetworkConnection(domain);
            cout << endl;
        }

        void run() {
            int choice;
            bool running = true;

            cout << "Endpoint Security Monitor initialized successfully!" << endl;

            while (running) {
                displayMenu();
                cin >> choice;

                switch (choice) {
                    case 1:
                        showMonitoredFiles();
                        break;
                    case 2:
                        showMonitoredProcesses();
                        break;
                    case 3:
                        showMonitoredDomains();
                        break;
                    case 4:
                        simulateFileChange();
                        break;
                    case 5:
                        simulateProcessStart();
                        break;
                    case 6:
                        simulateNetworkActivity();
                        break;
                    case 7:
                        threatAnalyzer.performFullSystemScan();
                        break;
                    case 8:
                        cout << "\nShutting down Endpoint Security Monitor..." << endl;
                        cout << "Thank you for using the security monitor!" << endl;
                        running = false;
                        break;
                    default:
                        cout << "\nInvalid choice! Please enter a number between 1-8." << endl;
                        break;
                }

                if (running) {
                    cout << "Press Enter to continue...";
                    cin.ignore();
                    cin.get();
                }
            }
        }
};

// Main Function
int main() {
    try {
        Simulator simulator;
        simulator.run();
    } catch (const exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }
    
    return 0;
}