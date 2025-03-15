# ThePhish - Automated Phishing Email Analysis Tool

ThePhish is an automated phishing email analysis tool that integrates with TheHive, Cortex, and MISP to provide comprehensive analysis and threat intelligence sharing capabilities.

## Features

- Automated email monitoring and analysis
- Integration with TheHive for case management
- Integration with Cortex for automated indicator analysis
- Integration with MISP for threat intelligence sharing
- Risk scoring and classification of potential phishing emails
- Detailed analysis of email headers, content, and attachments
- Extraction and analysis of URLs, domains, and other indicators
- Continuous monitoring mode for real-time analysis

## Prerequisites

- Python 3.8 or higher
- An up-and-running instance of TheHive
- An up-and-running instance of Cortex
- An up-and-running instance of MISP
- A dedicated email address for receiving potential phishing emails
- Linux-based operating system

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/thephish.git
cd thephish
```

2. Create a virtual environment and activate it:
```bash
python3 -m venv venv
source venv/bin/activate
```

3. Install the required dependencies:
```bash
pip install -r requirements.txt
```

## Configuration

Copy the example configuration file and modify it with your settings:

```bash
cp config.json.example config.json
```

Edit `config.json` with your specific configuration:

```json
{
  "thehive": {
    "base_url": "http://thehive-instance.example.com",
    "api_key": "YOUR_THEHIVE_API_KEY"
  },
  "cortex": {
    "base_url": "http://cortex-instance.example.com",
    "api_key": "YOUR_CORTEX_API_KEY"
  },
  "misp": {
    "base_url": "http://misp-instance.example.com",
    "api_key": "YOUR_MISP_API_KEY"
  },
  "email": {
    "address": "phish@example.com",
    "imap_server": "imap.example.com",
    "username": "email_username",
    "password": "email_password"
  },
  "logging": {
    "level": "INFO",
    "file": "thephish.log"
  }
}
```

## Usage

ThePhish can be run in two modes:

### Single Run Mode

Process all unread emails once and exit:

```bash
python main.py --config config.json
```

### Continuous Mode

Monitor the email inbox continuously for new messages:

```bash
python main.py --config config.json --continuous --interval 300
```

Options:
- `--config`: Path to configuration file (default: config.json)
- `--continuous`: Run in continuous monitoring mode
- `--interval`: Seconds between checks in continuous mode (default: 300)

## Components

### Email Handler (email_handler.py)
- Connects to the email server
- Fetches and parses unread emails
- Handles email processing status

### Phishing Analyzer (analysis.py)
- Analyzes emails for phishing indicators
- Extracts URLs, domains, and other indicators
- Calculates risk scores
- Identifies suspicious patterns

### TheHive Integration (thehive_client.py)
- Creates alerts and cases in TheHive
- Adds observables and artifacts
- Updates case status and details

### Cortex Integration (cortex_client.py)
- Submits indicators for analysis
- Retrieves and processes analysis results
- Supports multiple analyzer types

### MISP Integration (misp_client.py)
- Creates events for sharing threat intelligence
- Links related indicators and analysis results
- Searches for similar events

## Logging

Logs are written to both console and file (default: thephish.log). The log level can be configured in config.json.

Example log output:
```
2023-07-20 10:15:30,123 - INFO - Starting ThePhish in continuous mode (interval: 300s)
2023-07-20 10:15:31,234 - INFO - Successfully connected to email server
2023-07-20 10:15:32,345 - INFO - Found 2 unread emails
2023-07-20 10:15:33,456 - INFO - Created TheHive case THC#123
2023-07-20 10:15:34,567 - INFO - Created MISP event 456
```

## Error Handling

ThePhish includes comprehensive error handling:
- Connection failures are logged and retried
- Processing errors are caught and logged
- Individual email processing failures don't affect other emails
- Graceful shutdown on keyboard interrupt

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Security Considerations

- Store API keys and credentials securely
- Use HTTPS for all API connections
- Regularly update dependencies
- Monitor logs for unusual activity
- Follow security best practices for email handling

## Troubleshooting

### Common Issues

1. Email Connection Failures
   - Check email server settings
   - Verify credentials
   - Ensure server allows IMAP access

2. API Integration Issues
   - Verify API keys
   - Check instance URLs
   - Ensure API endpoints are accessible

3. Analysis Errors
   - Check log files for details
   - Verify Cortex analyzers are available
   - Ensure sufficient system resources

### Debug Mode

Enable DEBUG level logging in config.json for more detailed logs:

```json
{
  "logging": {
    "level": "DEBUG",
    "file": "thephish.log"
  }
}
```

## Support

For issues and feature requests, please create an issue in the GitHub repository.
