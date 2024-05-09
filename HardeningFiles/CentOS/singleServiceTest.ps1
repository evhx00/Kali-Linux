## Test with input


function Title
{
	param (
		[string]$Title = 'Services Menu'
	)

	Write-Host "*---------------* $Title *---------------*"
	Write-Host "1: Press '1' Disable Services."
	Write-Host "2: Press '2' Enable Services."
	Write-Host "Q: Press 'Q' to quit."
}

do
{
	Title
	$input = Read-Host "Please make a selection"
	switch($input)
	{
		'1'
		{
            Write-Warning 'Disabling Windows services...'
            # Display Services
            Get-Service CryptSvc | %{if($_.Satus -eq "Running") {Stop-Service CryptSvc}}
        
            Get-Service -Name CryptSvc | Select-Object -Property *
        
            echo 'Services Disabled!'
        }
		'2'
		{
            Write-Warning 'Enabling Windows services...'
            # Display Services
            Get-Service CryptSvc | %{if($_.Satus -eq "Stopped") {Start-Service CryptSvc}}
        
            Get-Service -Name CryptSvc | Select-Object -Property *
        
            echo 'Services Enabled!'
		}
		'q'
		{
			return
		}
	}
	pause
}
until($input -eq 'q')

