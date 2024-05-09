
    Write-Warning 'Enabling Windows services...'
    # Display Services
    Get-Service CryptSvc | %{if($_.Satus -eq "Stopped") {Start-Service CryptSvc}}

    Get-Service -Name CryptSvc | Select-Object -Property *

    echo 'Services Enabled!'