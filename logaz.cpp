#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <regex>
#include <chrono>
#include <iomanip>
#include <algorithm>
#include <filesystem>

class LogAnalyzer
{
public:
    struct LogEntry
    {
        std::string timestamp;
        std::string level;
        std::string message;
        std::string ip_address;
        std::string user_agent;
    };

private:
    // Storage for log analysis results
    std::vector<LogEntry> parsed_logs;
    std::unordered_map<std::string, int> error_counts;
    std::unordered_map<std::string, int> ip_access_count;
    std::unordered_set<std::string> unique_ips;

    std::regex apache_log_pattern
    {R"((\S+) (\S+) (\S+) \[([^\]]+)\] "([^"]*)" (\d+) (\d+))"};
    std::regex error_log_pattern{R"((\[.*?\]) (\[.*?\]) (.*))"};

    public:
        bool parseLogFile(const std::string &filename)
        {
            std::ifstream log_file(filename);
            if (!log_file.is_open())
            {
                std::cerr << "Error: Unable to open file " << filename << std::endl;
                return false;
            }

            std::string line;
            while (std::getline(log_file, line))
            {
                LogEntry entry;

                std::smatch matches;
                if (std::regex_search(line, matches, apache_log_pattern))
                {
                    entry.ip_address = matches[1];
                    entry.timestamp = matches[4];
                    entry.status_code = std::stoi(matches[6]);
                    entry.message = matches[5];
                }
                else if (std::regex_search(line, matches, error_log_pattern))
                {
                    entry.timestamp = matches[1];
                    entry.level = matches[2];
                    entry.message = matches[3];
                }
                else
                {
                    entry.message = line;
                }

                updateAnalysisTrackers(entry);
                parsed_logs.push_back(entry);
            }

            return true;
        }

    private:
        void updateAnalysisTrackers(const LogEntry &entry)
        {
            if (!entry.level.empty())
            {
                error_counts[entry.level]++;
            }

            if (!entry.ip_address.empty())
            {
                ip_access_count[entry.ip_address]++;
                unique_ips.insert(entry.ip_address);
            }
        }

    public:
        void generateReport(std::ostream &out = std::cout)
        {
            out << "=== Log Analysis Report ===" << std::endl;

            out << "\nError Summary:" << std::endl;
            for (const auto &error : error_counts)
            {
                out << error.first << ": " << error.second << " occurrences" << std::endl;
            }

            out << "\nIP Access Analysis:" << std::endl;
            out << "Total Unique IPs: " << unique_ips.size() << std::endl;
            out << "Top 5 Most Active IPs:" << std::endl;

            std::vector<std::pair<std::string, int>> sorted_ips(
                ip_access_count.begin(), ip_access_count.end());
            std::sort(sorted_ips.begin(), sorted_ips.end(),
                      [](const auto &a, const auto &b)
                      { return a.second > b.second; });

            for (size_t i = 0; i < std::min(sorted_ips.size(), size_t(5)); ++i)
            {
                out << sorted_ips[i].first << ": " << sorted_ips[i].second << " accesses" << std::endl;
            }

            out << "\nUnusual Activity Detection:" << std::endl;
            detectUnusualActivity(out);
        }

    private:
        void detectUnusualActivity(std::ostream & out)
        {
            int total_entries = parsed_logs.size();
            for (const auto &error : error_counts)
            {
                double error_rate = (error.second * 100.0) / total_entries;
                if (error_rate > 10.0)
                { 
                    out << "ALERT: High " << error.first << " error rate: "
                        << error_rate << "%" << std::endl;
                }
            }

            for (const auto &ip_entry : ip_access_count)
            {
                double access_rate = (ip_entry.second * 100.0) / total_entries;
                if (access_rate > 20.0)
                { 
                    out << "SUSPICIOUS: IP " << ip_entry.first
                        << " has excessive access: " << access_rate << "%" << std::endl;
                }
            }
        }

    public:
        void exportToCSV(const std::string &output_filename)
        {
            std::ofstream csv_file(output_filename);
            if (!csv_file.is_open())
            {
                std::cerr << "Error: Unable to create CSV file " << output_filename << std::endl;
                return;
            }

            csv_file << "Timestamp,Level,Message,IP Address,Status Code" << std::endl;

            for (const auto &entry : parsed_logs)
            {
                csv_file << entry.timestamp << ","
                         << entry.level << ","
                         << "\"" << entry.message << "\","
                         << entry.ip_address << ","
                         << entry.status_code << std::endl;
            }

            csv_file.close();
        }

        void reset()
        {
            parsed_logs.clear();
            error_counts.clear();
            ip_access_count.clear();
            unique_ips.clear();
        }
    };

    int main(int argc, char *argv[])
    {
        if (argc < 2)
        {
            std::cerr << "Usage: " << argv[0] << " <log_file_path> [output_csv]" << std::endl;
            return 1;
        }

        LogAnalyzer analyzer;

        if (!analyzer.parseLogFile(argv[1]))
        {
            return 1;
        }

        analyzer.generateReport();

        if (argc > 2)
        {
            analyzer.exportToCSV(argv[2]);
            std::cout << "Log data exported to " << argv[2] << std::endl;
        }

        return 0;
    }