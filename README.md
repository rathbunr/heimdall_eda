# RITC Security Automation Collection

An Enterprise Event-Driven Ansible collection that provides integration with MITRE HEIMDALL2 vulnerability management platform for automated security compliance remediation.

## Overview

This collection enables real-time monitoring of security control failures from HEIMDALL2 and automated remediation through Event-Driven Ansible, supporting compliance frameworks including DISA STIG, NIST 800-53, and CIS benchmarks.

## Installation

```bash
ansible-galaxy collection install ritcsusa.security_automation
```

## Quick Start

1. Configure your HEIMDALL2 server with API access
2. Create a rulebook using the provided example
3. Run with ansible-rulebook

## Plugin: heimdall

Event source plugin that monitors HEIMDALL2 for failed security controls.

### Parameters:
- `heimdall_url` (required): HEIMDALL2 server URL
- `api_key` (required): API key for authentication  
- `poll_interval` (optional): Polling interval in seconds (default: 300)
- `ssl_verify` (optional): SSL verification (default: false)
- `target_controls` (optional): List of specific controls to monitor

### Events Generated:
- `heimdall2_startup`: Plugin initialization and configuration
- `heimdall2_connectivity`: API connectivity status updates
- `heimdall2_vulnerability`: Failed security control notifications
- `heimdall2_error`: Error conditions and diagnostics

## Example Usage

See `playbooks/examples/heimdall_monitoring.yml` for a complete working example.

## Support

- Documentation: https://github.com/rathbunr/ritc.eda
- Issues: https://github.com/rathbunr/ritc.eda/issues
- Company: Rathbun IT Consulting

## License

Apache License 2.0
