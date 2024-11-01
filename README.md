# Email Authentication Validator

A PowerShell GUI tool for validating email authentication records (SPF, DKIM, and DMARC) for multiple domains.

## Features

- **Batch Domain Processing**: Check multiple domains at once
- **Comprehensive Checks**:
  - SPF (Sender Policy Framework) validation
  - DKIM (DomainKeys Identified Mail) verification
  - DMARC (Domain-based Message Authentication) policy checking
- **Modern GUI Interface**:
  - Clean black and white theme
  - Progress tracking
  - Grid view results
- **Export Capabilities**: Save results to CSV
- **Detailed Record View**: Inspect full DNS records for each domain

## Requirements

### For PowerShell Script (.ps1)
- PowerShell 5.1 or later
- Windows OS
- DNS resolution capabilities
- Required PowerShell modules:
  - System.Windows.Forms
  - System.Drawing

### For Executable (.exe)
- Windows OS
- DNS resolution capabilities
- No PowerShell or additional modules required

## Installation

### PowerShell Script
1. Download the `bulk-checker.ps1` script
2. Right-click the script and select "Properties"
3. Check the "Unblock" box if present
4. Click "Apply" and "OK"

### Executable
1. Download the `bulk-checker.exe`
2. No additional installation steps required

## Usage

### Running the Application

You have two options to run the application:

1. **PowerShell Script**:
   - Right-click the script and select "Run with PowerShell" or
   - Open PowerShell and navigate to the script directory:
   ```powershell
   .\bulk-checker.ps1
   ```

2. **Executable**:
   - Double-click `bulk-checker.exe` to run directly
   - No PowerShell environment needed
