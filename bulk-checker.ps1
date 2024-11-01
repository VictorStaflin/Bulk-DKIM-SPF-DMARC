# Add framework version check at the start of your script
if ($PSVersionTable.PSVersion.Major -lt 5) {
    [System.Windows.Forms.MessageBox]::Show(
        "This application requires PowerShell 5.1 or later.",
        "Compatibility Error",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
    )
    exit 1
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

function Resolve-DnsRecord {
    param (
        [string]$Domain,
        [string]$RecordType
    )
    try {
        Write-Verbose "Resolving $RecordType record for $Domain"
        $results = @(Resolve-DnsName -Name $Domain -Type $RecordType -ErrorAction Stop)
        Write-Verbose "Found $($results.Count) records"
        return $results
    }
    catch {
        Write-Verbose "DNS resolution failed for $Domain ($RecordType): $($_.Exception.Message)"
        return $null
    }
}

function Test-SPFRecord {
    param ([string]$Domain)
    Write-Verbose "Testing SPF for $Domain"
    try {
        $spfRecord = @(Resolve-DnsName -Name $Domain -Type TXT -ErrorAction Stop | 
            Where-Object { $_.Strings -like 'v=spf1*' } | 
            Select-Object -First 1)

        if ($spfRecord) {
            $spfText = $spfRecord.Strings -join ''
            Write-Verbose "Found SPF record: $spfText"
            return @{
                Exists = $true
                Record = $spfText
                Mechanism = ($spfText -split ' ' | Where-Object { $_ -match '^(a|mx|ip4|ip6|include|redirect|exp)' }) -join ', '
            }
        }
        Write-Verbose "No SPF record found"
        return @{ Exists = $false }
    }
    catch {
        Write-Verbose "SPF check failed: $($_.Exception.Message)"
        return @{ Exists = $false; Error = $_.Exception.Message }
    }
}

function Test-DKIMRecord {
    param ([string]$Domain)
    Write-Verbose "Testing DKIM for $Domain"
    try {
        $selectors = @('default', 'google', 'selector1', 'selector2')
        $dkimResults = @()
        
        foreach ($selector in $selectors) {
            $dkimDomain = "${selector}._domainkey.$Domain"
            Write-Verbose "Checking DKIM selector: $dkimDomain"
            
            $dkimRecord = @(Resolve-DnsName -Name $dkimDomain -Type TXT -ErrorAction Stop)
            
            if ($dkimRecord) {
                $dkimText = $dkimRecord.Strings -join ''
                if ($dkimText -match 'v=DKIM1') {
                    Write-Verbose "Found valid DKIM record for selector $selector"
                    $dkimResults += @{
                        Exists = $true
                        Record = $dkimText
                        Selector = $selector
                    }
                }
            }
        }

        if ($dkimResults.Count -gt 0) {
            return @{
                Exists = $true
                Count = $dkimResults.Count
                Details = $dkimResults
            }
        }
        
        Write-Verbose "No DKIM records found"
        return @{ Exists = $false }
    }
    catch {
        Write-Verbose "DKIM check failed: $($_.Exception.Message)"
        return @{ Exists = $false; Error = $_.Exception.Message }
    }
}

function Test-DMARCRecord {
    param ([string]$Domain)
    Write-Verbose "Testing DMARC for $Domain"
    try {
        $dmarcDomain = "_dmarc.$Domain"
        $dmarcRecord = @(Resolve-DnsName -Name $dmarcDomain -Type TXT -ErrorAction Stop | 
            Where-Object { $_.Strings -like 'v=DMARC1*' } |
            Select-Object -First 1)
        
        if ($dmarcRecord) {
            $recordText = $dmarcRecord.Strings -join ''
            Write-Verbose "Found DMARC record: $recordText"
            
            $policy = if ($recordText -match 'p=(none|quarantine|reject)') { $matches[1] } else { 'Unknown' }
            
            return @{
                Exists = $true
                Record = $recordText
                Policy = $policy
            }
        }
        
        Write-Verbose "No DMARC record found"
        return @{ Exists = $false }
    }
    catch {
        Write-Verbose "DMARC check failed: $($_.Exception.Message)"
        return @{ Exists = $false; Error = $_.Exception.Message }
    }
}

# Add new function for domain extraction
function Get-DomainsFromCsv {
    param (
        [string]$FilePath
    )

    try {
        # Import raw content and clean empty lines
        $domains = Get-Content -Path $FilePath | 
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            ForEach-Object {
                # Trim and clean domain
                $domain = $_.Trim().ToLower()
                
                # Basic domain validation
                if ($domain -match '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$') {
                    $domain
                }
            } | Select-Object -Unique

        return $domains
    }
    catch {
        throw "CSV Import Error: $($_.Exception.Message)"
    }
}

# Add these functions at the beginning of the script

function Start-BatchProcessing {
    param (
        [string[]]$Domains,
        [int]$BatchSize = 10,  # Reduced batch size for better control
        [System.Windows.Forms.ProgressBar]$Progress = $null
    )

    $results = @()
    
    foreach ($domain in $Domains) {
        Write-Verbose "Processing domain: $domain"
        
        # Process each domain synchronously for now
        $spf = Test-SPFRecord -Domain $domain
        $dkim = Test-DKIMRecord -Domain $domain
        $dmarc = Test-DMARCRecord -Domain $domain
        
        $results += @{
            Domain = $domain
            SPF = $spf
            DKIM = $dkim
            DMARC = $dmarc
        }
        
        # Update progress if progress bar exists
        if ($Progress) {
            $progressPercentage = [Math]::Round(($results.Count / $Domains.Count) * 100)
            $Progress.Value = $progressPercentage
        }
    }
    
    return $results
}

# Main Form - modern black and white theme
$form = New-Object System.Windows.Forms.Form
$form.Text = 'Email Authentication Validator'
$form.Size = New-Object System.Drawing.Size(1400, 900)
$form.StartPosition = 'CenterScreen'
$form.BackColor = [System.Drawing.Color]::White

# Left Panel - Input and Controls
$leftPanel = New-Object System.Windows.Forms.Panel
$leftPanel.Location = New-Object System.Drawing.Point(20, 20)
$leftPanel.Size = New-Object System.Drawing.Size(350, 850)
$leftPanel.BackColor = [System.Drawing.Color]::White
$leftPanel.BorderStyle = 'None'
$form.Controls.Add($leftPanel)

# Input Group
$inputGroup = New-Object System.Windows.Forms.GroupBox
$inputGroup.Location = New-Object System.Drawing.Point(10, 10)
$inputGroup.Size = New-Object System.Drawing.Size(330, 300)
$inputGroup.Text = "DOMAIN INPUT"
$inputGroup.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$inputGroup.ForeColor = [System.Drawing.Color]::Black
$leftPanel.Controls.Add($inputGroup)

# Domains Input Label
$domainsLabel = New-Object System.Windows.Forms.Label
$domainsLabel.Location = New-Object System.Drawing.Point(10, 20)
$domainsLabel.Size = New-Object System.Drawing.Size(310, 20)
$domainsLabel.Text = 'Enter Domains (One per line):'
$domainsLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$inputGroup.Controls.Add($domainsLabel)

# Domains TextBox - modern style
$domainsTextBox = New-Object System.Windows.Forms.TextBox
$domainsTextBox.Location = New-Object System.Drawing.Point(10, 45)
$domainsTextBox.Size = New-Object System.Drawing.Size(310, 180)
$domainsTextBox.Multiline = $true
$domainsTextBox.ScrollBars = 'Vertical'
$domainsTextBox.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$domainsTextBox.BorderStyle = 'FixedSingle'
$inputGroup.Controls.Add($domainsTextBox)

# Import Button - flat style
$importCsvButton = New-Object System.Windows.Forms.Button
$importCsvButton.Location = New-Object System.Drawing.Point(10, 235)
$importCsvButton.Size = New-Object System.Drawing.Size(310, 35)
$importCsvButton.Text = 'IMPORT FROM FILE'
$importCsvButton.FlatStyle = 'Flat'
$importCsvButton.BackColor = [System.Drawing.Color]::White
$importCsvButton.ForeColor = [System.Drawing.Color]::Black
$importCsvButton.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$importCsvButton.FlatAppearance.BorderColor = [System.Drawing.Color]::Black
$inputGroup.Controls.Add($importCsvButton)

# Options Group
$optionsGroup = New-Object System.Windows.Forms.GroupBox
$optionsGroup.Location = New-Object System.Drawing.Point(10, 320)
$optionsGroup.Size = New-Object System.Drawing.Size(330, 280)
$optionsGroup.Text = "VALIDATION OPTIONS"
$optionsGroup.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$leftPanel.Controls.Add($optionsGroup)

# Validation Options - modern checkboxes
$checkSpf = New-Object System.Windows.Forms.CheckBox
$checkSpf.Location = New-Object System.Drawing.Point(20, 30)
$checkSpf.Size = New-Object System.Drawing.Size(290, 24)
$checkSpf.Text = "Check SPF Records"
$checkSpf.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$checkSpf.Checked = $true
$optionsGroup.Controls.Add($checkSpf)

$checkDkim = New-Object System.Windows.Forms.CheckBox
$checkDkim.Location = New-Object System.Drawing.Point(20, 60)
$checkDkim.Size = New-Object System.Drawing.Size(290, 24)
$checkDkim.Text = "Check DKIM Records"
$checkDkim.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$checkDkim.Checked = $true
$optionsGroup.Controls.Add($checkDkim)

$autoDetectDkim = New-Object System.Windows.Forms.CheckBox
$autoDetectDkim.Location = New-Object System.Drawing.Point(40, 90)
$autoDetectDkim.Size = New-Object System.Drawing.Size(270, 24)
$autoDetectDkim.Text = "Auto-detect DKIM Selectors"
$autoDetectDkim.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$autoDetectDkim.Checked = $true
$optionsGroup.Controls.Add($autoDetectDkim)

# Action Buttons Group - adjust position and size
$actionGroup = New-Object System.Windows.Forms.GroupBox
$actionGroup.Location = New-Object System.Drawing.Point(10, 610)
$actionGroup.Size = New-Object System.Drawing.Size(330, 220)
$actionGroup.Text = "ACTIONS"
$actionGroup.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$leftPanel.Controls.Add($actionGroup)

# Button spacing - evenly distributed
$validateButton = New-Object System.Windows.Forms.Button
$validateButton.Location = New-Object System.Drawing.Point(10, 30)
$validateButton.Size = New-Object System.Drawing.Size(310, 40)
$validateButton.Text = 'VALIDATE DOMAINS'
$validateButton.FlatStyle = 'Flat'
$validateButton.BackColor = [System.Drawing.Color]::Black
$validateButton.ForeColor = [System.Drawing.Color]::White
$validateButton.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$validateButton.FlatAppearance.BorderSize = 0
$actionGroup.Controls.Add($validateButton)

$exportButton = New-Object System.Windows.Forms.Button
$exportButton.Location = New-Object System.Drawing.Point(10, 80)
$exportButton.Size = New-Object System.Drawing.Size(310, 40)
$exportButton.Text = 'EXPORT TO CSV'
$exportButton.FlatStyle = 'Flat'
$exportButton.BackColor = [System.Drawing.Color]::White
$exportButton.ForeColor = [System.Drawing.Color]::Black
$exportButton.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$exportButton.FlatAppearance.BorderColor = [System.Drawing.Color]::Black
$actionGroup.Controls.Add($exportButton)

$detailsButton = New-Object System.Windows.Forms.Button
$detailsButton.Location = New-Object System.Drawing.Point(10, 130)
$detailsButton.Size = New-Object System.Drawing.Size(310, 40)
$detailsButton.Text = 'VIEW DETAILS'
$detailsButton.FlatStyle = 'Flat'
$detailsButton.BackColor = [System.Drawing.Color]::White
$detailsButton.ForeColor = [System.Drawing.Color]::Black
$detailsButton.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$detailsButton.FlatAppearance.BorderColor = [System.Drawing.Color]::Black
$actionGroup.Controls.Add($detailsButton)

$infoButton = New-Object System.Windows.Forms.Button
$infoButton.Location = New-Object System.Drawing.Point(10, 180)
$infoButton.Size = New-Object System.Drawing.Size(310, 40)
$infoButton.Text = 'ABOUT / HELP'
$infoButton.FlatStyle = 'Flat'
$infoButton.BackColor = [System.Drawing.Color]::White
$infoButton.ForeColor = [System.Drawing.Color]::Black
$infoButton.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$infoButton.FlatAppearance.BorderColor = [System.Drawing.Color]::Black
$actionGroup.Controls.Add($infoButton)

# Results Grid - modern styling with subtle selection
$resultsGrid = New-Object System.Windows.Forms.DataGridView
$resultsGrid.Location = New-Object System.Drawing.Point(390, 20)
$resultsGrid.Size = New-Object System.Drawing.Size(980, 820)
$resultsGrid.BackgroundColor = [System.Drawing.Color]::White
$resultsGrid.BorderStyle = 'None'
$resultsGrid.GridColor = [System.Drawing.Color]::LightGray
$resultsGrid.CellBorderStyle = 'SingleHorizontal'
$resultsGrid.ColumnHeadersBorderStyle = 'None'
$resultsGrid.EnableHeadersVisualStyles = $false

# Header styling - black background with white text
$resultsGrid.ColumnHeadersDefaultCellStyle.BackColor = [System.Drawing.Color]::Black
$resultsGrid.ColumnHeadersDefaultCellStyle.ForeColor = [System.Drawing.Color]::White
$resultsGrid.ColumnHeadersDefaultCellStyle.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$resultsGrid.ColumnHeadersDefaultCellStyle.SelectionBackColor = [System.Drawing.Color]::Black
$resultsGrid.ColumnHeadersHeight = 32

# Cell styling - with subtle selection highlight
$resultsGrid.DefaultCellStyle.BackColor = [System.Drawing.Color]::White
$resultsGrid.DefaultCellStyle.ForeColor = [System.Drawing.Color]::Black
$resultsGrid.DefaultCellStyle.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$resultsGrid.DefaultCellStyle.SelectionBackColor = [System.Drawing.Color]::FromArgb(245, 245, 245)
$resultsGrid.DefaultCellStyle.SelectionForeColor = [System.Drawing.Color]::Black

# Alternate row styling - even more subtle
$resultsGrid.AlternatingRowsDefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(252, 252, 252)
$resultsGrid.AlternatingRowsDefaultCellStyle.SelectionBackColor = [System.Drawing.Color]::FromArgb(245, 245, 245)
$resultsGrid.AlternatingRowsDefaultCellStyle.SelectionForeColor = [System.Drawing.Color]::Black

# General settings
$resultsGrid.RowHeadersVisible = $false
$resultsGrid.AllowUserToAddRows = $false
$resultsGrid.SelectionMode = 'FullRowSelect'
$resultsGrid.MultiSelect = $false
$resultsGrid.ReadOnly = $true
$resultsGrid.ColumnCount = 6
$form.Controls.Add($resultsGrid)

# Configure columns
$resultsGrid.Columns[0].Name = 'DOMAIN'
$resultsGrid.Columns[1].Name = 'SPF'
$resultsGrid.Columns[2].Name = 'SPF MECHANISM'
$resultsGrid.Columns[3].Name = 'DKIM'
$resultsGrid.Columns[4].Name = 'DMARC'
$resultsGrid.Columns[5].Name = 'STATUS'
$resultsGrid.AutoSizeColumnsMode = 'Fill'

# Import CSV Button
$importCsvButton.Add_Click({
    $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openFileDialog.Filter = "CSV Files (*.csv)|*.csv|All Files (*.*)|*.*"
    $openFileDialog.Title = "Select file with domains"
    
    if ($openFileDialog.ShowDialog() -eq 'OK') {
        try {
            $uniqueDomains = Get-DomainsFromCsv -FilePath $openFileDialog.FileName

            if ($uniqueDomains.Count -eq 0) {
                [System.Windows.Forms.MessageBox]::Show(
                    "No valid domains found in the file. Please check the file format.", 
                    "Import Error",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Warning
                )
                return
            }
            
            # Add domains to text box
            $domainsTextBox.Text = $uniqueDomains -join "`r`n"
            
            [System.Windows.Forms.MessageBox]::Show(
                "Imported $($uniqueDomains.Count) unique domains.", 
                "Import Successful"
            )
        }
        catch {
            [System.Windows.Forms.MessageBox]::Show(
                "Error importing file: $($_.Exception.Message)", 
                "Import Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
        }
    }
})

# Validate Button
$validateButton.Add_Click({
    if ([string]::IsNullOrWhiteSpace($domainsTextBox.Text)) {
        [System.Windows.Forms.MessageBox]::Show("Please enter at least one domain.", "No Domains")
        return
    }

    $resultsGrid.Rows.Clear()
    $domains = @($domainsTextBox.Text -split "`r`n" | 
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) })

    if ($domains.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("Please enter valid domains.", "Invalid Input")
        return
    }
    
    # Show progress form
    $progressForm = New-Object System.Windows.Forms.Form
    $progressForm.Text = 'Processing Domains'
    $progressForm.Size = New-Object System.Drawing.Size(400, 100)
    $progressForm.StartPosition = 'CenterScreen'
    
    $progressBar = New-Object System.Windows.Forms.ProgressBar
    $progressBar.Location = New-Object System.Drawing.Point(10, 20)
    $progressBar.Size = New-Object System.Drawing.Size(360, 30)
    $progressBar.Minimum = 0
    $progressBar.Maximum = 100
    $progressBar.Value = 0
    $progressForm.Controls.Add($progressBar)
    
    try {
        $progressForm.Show()
        $form.Refresh()
        
        # Process domains - pass the progress bar
        $results = Start-BatchProcessing -Domains $domains -Progress $progressBar
        
        if ($null -ne $results) {
            foreach ($result in $results) {
                if ($null -ne $result) {
                    $spfStatus = if ($result.SPF -and $result.SPF.Exists) { "Found" } else { "No SPF Record" }
                    $spfMechanism = if ($result.SPF -and $result.SPF.Exists -and $result.SPF.Mechanism) { 
                        $result.SPF.Mechanism 
                    } else { 
                        "N/A" 
                    }
                    $dkimStatus = if ($result.DKIM -and $result.DKIM.Exists) { 
                        "Found ($($result.DKIM.Count))" 
                    } else { 
                        "No DKIM Records" 
                    }
                    $dmarcStatus = if ($result.DMARC -and $result.DMARC.Exists) { 
                        "Found (p=$($result.DMARC.Policy))" 
                    } else { 
                        "No DMARC Record" 
                    }
                    
                    # Determine overall status
                    $overallStatus = if (
                        ($result.SPF -and $result.SPF.Exists) -and 
                        ($result.DKIM -and $result.DKIM.Exists) -and 
                        ($result.DMARC -and $result.DMARC.Exists)
                    ) {
                        "COMPLETE"
                    } else {
                        "INCOMPLETE"
                    }
                    
                    [void]$resultsGrid.Rows.Add(
                        $result.Domain,
                        $spfStatus,
                        $spfMechanism,
                        $dkimStatus,
                        $dmarcStatus,
                        $overallStatus
                    )
                }
            }
        }
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show(
            "An error occurred: $($_.Exception.Message)", 
            "Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
    }
    finally {
        if ($null -ne $progressForm -and -not $progressForm.IsDisposed) {
            $progressForm.Close()
            $progressForm.Dispose()
        }
    }
})

# Export Button
$exportButton.Add_Click({
    $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveFileDialog.Filter = "CSV Files (*.csv)|*.csv"
    $saveFileDialog.Title = "Export Domain Validation Results"
    $saveFileDialog.ShowDialog()

    if ($saveFileDialog.FileName -ne "") {
        $exportData = @()
        foreach ($row in $resultsGrid.Rows) {
            if ($row.Cells[0].Value -ne $null) {
                $exportData += [PSCustomObject]@{
                    Domain = $row.Cells[0].Value
                    SPF = $row.Cells[1].Value
                    SPFMechanism = $row.Cells[2].Value
                    DKIM = $row.Cells[3].Value
                    DMARC = $row.Cells[4].Value
                    Status = $row.Cells[5].Value
                }
            }
        }
        $exportData | Export-Csv -Path $saveFileDialog.FileName -NoTypeInformation
        [System.Windows.Forms.MessageBox]::Show("Results exported successfully!", "Export Complete")
    }
})

# Details Button
$detailsButton.Add_Click({
    if ($resultsGrid.SelectedRows.Count -gt 0) {
        $selectedDomain = $resultsGrid.SelectedRows[0].Cells[0].Value
        
        $spf = Test-SPFRecord -Domain $selectedDomain
        $dkim = Test-DKIMRecord -Domain $selectedDomain
        $dmarc = Test-DMARCRecord -Domain $selectedDomain

        $detailsMessage = "Domain: $selectedDomain`n`n"
        
        $detailsMessage += "SPF Record:`n"
        if ($spf.Exists) {
            $detailsMessage += $spf.Record + "`n"
        } else {
            $detailsMessage += "No SPF Record Found`n"
        }
        
        $detailsMessage += "`nDKIM Records:`n"
        if ($dkim.Exists) {
            $detailsMessage += "Found " + $dkim.Count + " valid DKIM record(s)`n"
            foreach ($record in $dkim.Details) {
                $detailsMessage += "-----------------`n"
                $detailsMessage += "Selector: " + $record.Selector + "`n"
                $detailsMessage += "DKIM Domain: " + $record.Domain + "`n"
                $detailsMessage += "Version: " + $record.Version + "`n"
                $detailsMessage += "Key Type: " + $record.Key + "`n"
                $detailsMessage += "Hash Algorithm: " + $record.Hash + "`n"
                if ($record.Notes) { 
                    $detailsMessage += "Notes: " + $record.Notes + "`n" 
                }
                $detailsMessage += "Service Type: " + $record.Service + "`n"
                $detailsMessage += "Full Record: " + $record.Record + "`n"
            }
        } else {
            if ($dkim.Message) {
                $detailsMessage += $dkim.Message + "`n"
            } else {
                $detailsMessage += "No DKIM Records Found`n"
            }
        }
        
        $detailsMessage += "`nDMARC Record:`n"
        if ($dmarc.Exists) {
            $detailsMessage += "Domain: " + $dmarc.Domain + "`n"
            $detailsMessage += "Record: " + $dmarc.Record + "`n"
            $detailsMessage += "Policy: " + $dmarc.Policy + "`n"
            if ($dmarc.SubdomainPolicy) {
                $detailsMessage += "Subdomain Policy: " + $dmarc.SubdomainPolicy + "`n"
            }
            $detailsMessage += "Enforcement Percentage: " + $dmarc.Percentage + "%"
        } else {
            if ($dmarc.Message) {
                $detailsMessage += $dmarc.Message
                if ($dmarc.Error) {
                    $detailsMessage += "`nError Details: " + $dmarc.Error
                }
            } else {
                $detailsMessage += "No DMARC Record Found"
            }
        }

        [System.Windows.Forms.MessageBox]::Show($detailsMessage, "Domain Details")
    }
    else {
        [System.Windows.Forms.MessageBox]::Show("Please select a domain from the results.", "No Selection")
    }
})

# Info Button Click Handler
$infoButton.Add_Click({
    $infoForm = New-Object System.Windows.Forms.Form
    $infoForm.Text = "About Email Authentication Validator"
    $infoForm.Size = New-Object System.Drawing.Size(600, 500)
    $infoForm.StartPosition = 'CenterParent'
    $infoForm.BackColor = [System.Drawing.Color]::White
    $infoForm.FormBorderStyle = 'FixedDialog'
    $infoForm.MaximizeBox = $false
    $infoForm.MinimizeBox = $false

    # Title Label
    $titleLabel = New-Object System.Windows.Forms.Label
    $titleLabel.Location = New-Object System.Drawing.Point(20, 20)
    $titleLabel.Size = New-Object System.Drawing.Size(540, 30)
    $titleLabel.Text = "Email Authentication Validator"
    $titleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Bold)
    $infoForm.Controls.Add($titleLabel)

    # Description TextBox
    $descriptionBox = New-Object System.Windows.Forms.RichTextBox
    $descriptionBox.Location = New-Object System.Drawing.Point(20, 60)
    $descriptionBox.Size = New-Object System.Drawing.Size(540, 330)
    $descriptionBox.BackColor = [System.Drawing.Color]::White
    $descriptionBox.ReadOnly = $true
    $descriptionBox.BorderStyle = 'None'
    $descriptionBox.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $descriptionBox.Text = @"
This application validates email authentication records for domains, checking three critical email security protocols:

1. SPF (Sender Policy Framework)
   • Verifies authorized email senders
   • Prevents email spoofing
   • Shows mechanisms used (IP4, IP6, Include, etc.)

2. DKIM (DomainKeys Identified Mail)
   • Validates email authenticity
   • Checks digital signatures
   • Auto-detects common selectors

3. DMARC (Domain-based Message Authentication)
   • Enforces domain-wide email policies
   • Shows policy settings (none/quarantine/reject)
   • Displays percentage and subdomain policies

Features:
• Batch processing of multiple domains
• Parallel processing for faster results
• Auto-detection of email providers
• Export results to CSV
• Detailed record viewing

Usage:
1. Enter domains (one per line) or import from file
2. Click 'Validate Domains' to start
3. View results in the grid
4. Export or view detailed results as needed

Performance:
• Optimized for large domain lists
• Processes domains in parallel
• Automatic error handling and retry
"@
    $infoForm.Controls.Add($descriptionBox)

    # Close Button
    $closeButton = New-Object System.Windows.Forms.Button
    $closeButton.Location = New-Object System.Drawing.Point(200, 410)
    $closeButton.Size = New-Object System.Drawing.Size(180, 35)
    $closeButton.Text = "CLOSE"
    $closeButton.FlatStyle = 'Flat'
    $closeButton.BackColor = [System.Drawing.Color]::Black
    $closeButton.ForeColor = [System.Drawing.Color]::White
    $closeButton.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $closeButton.FlatAppearance.BorderSize = 0
    $closeButton.Add_Click({ $infoForm.Close() })
    $infoForm.Controls.Add($closeButton)

    # Show the form
    $infoForm.ShowDialog()
})

# Show the form
$form.ShowDialog()
