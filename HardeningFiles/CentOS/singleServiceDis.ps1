
    Write-Warning 'Disabling Windows services...'
    # Display Services
    Get-Service CryptSvc | %{if($_.Satus -eq "Running") {Stop-Service CryptSvc}}

    Get-Service -Name CryptSvc | Select-Object -Property *

    echo 'Services Disabled!'