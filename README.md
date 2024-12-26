# Logaz - Log files analyzer

 a simple tool for log file analysis that provides robust parsing and extraction capabilities.

 ## key features 

 1- Flexible Log Parsing

- Supports multiple log formats (Apache-style and error logs)
- Uses regular expressions for robust parsing
- Extracts key information like timestamps, IP addresses, error levels, and status codes


2- Performs a comprehensive analysis

- Tracks error occurrences by type
- Monitors IP access patterns
- Identifies unique IP addresses
- Detects unusual activity based on error rates and access patterns


3- Reporting Capabilities

- Generates a detailed console report
- Highlights top 5 most active IPs
- Provides alerts for high error rates or suspicious access patterns

4- Data Export

Can export parsed logs to a CSV file for further analysis


4- Simple cli

Easy to use: ./logaz logfile.log [optional_output.csv]


## Build commands:

```bash
mkdir build && cd build
cmake ..
make
```

### Example usage:

```bash
# Basic analysis
./logaz apache.log

# Csv export
./logaz apache.log output.csv
```






