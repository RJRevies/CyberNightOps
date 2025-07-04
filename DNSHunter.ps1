# DNSHunter.ps1
# Logs DNS queries and compares them to known bad domains

# ----------------------
# Set file paths
# ----------------------
$dnsLogPath = "dns_log.csv"
$threatListPath = "known_bad_domains.txt"
$outputPath = "dns_suspicious.csv"

# ----------------------
# Read known bad domains into an array
# ----------------------
if (Test-Path $threatListPath) {
    $badDomains = Get-Content $threatListPath
} else {
    Write-Host "Threat list file not found: $threatListPath"
    exit
}

# ----------------------
# Get DNS logs from Windows Event Viewer
# ----------------------
try {
    $dnsEvents = Get-WinEvent -LogName "Microsoft-Windows-DNS-Client/Operational" -MaxEvents 200
} catch {
    Write-Host "Unable to read DNS Client logs. Make sure the log is enabled."
    exit
}

# ----------------------
# Create or clear output file
# ----------------------
"" | Out-File $outputPath

# ----------------------
# Check each DNS log for matches with known bad domains
# ----------------------
foreach ($event in $dnsEvents) {
    $msg = $event.Message

    foreach ($domain in $badDomains) {
        if ($msg -like "*$domain*") {
            $entry = "$($event.TimeCreated),$domain,$msg"
            Add-Content -Path $outputPath -Value $entry
        }
    }
}

Write-Host "`n✅ DNSHunter scan complete."
Write-Host "Results saved to: $outputPath"

