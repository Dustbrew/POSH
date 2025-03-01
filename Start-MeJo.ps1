Clear-Host
  Set-Location c:\admin\scripts\PSscripts\
  $env:PSModulePath = $env:PSModulePath + ";c:\admin\scripts\MyModules\"
 # text if 32 or 64 --------------------------------------------------------------------------------------------------
  if ($env:Processor_Architecture -ne 'x86') {
    
		$bit = 64
		$bittitle = "Windows Powershell-64Bit"
  else
  {
		$bit = 32
		$bittitle = "Windows Powershell-32Bit"
	
  }
	$KeyFile = "c:\admin\dat\keys\AES.key"
	$today = Get-Date
	$first = Get-Date -Year $today.Year -Month $today.Month -Day 1
	$days = [datetime]::DaysInMonth($today.Year, $today.Month)
    $header = "{0:MMMM yyyy}" -f $today
	$header_padding = [math]::Floor((19 - $header.Length) / 2) + $header.Length
	$first_padding = 3 * [int]$first.DayOfweek
	
  trap {
    $today -Format g | Out-File c:\admin\logs\errortime.txt
    $today | Out-File c:\admin\logs\error.txt -Append
    $error | Out-File c:\admin\logs\error.txt -Append
    continue
  }
  
  $host.ui.RawUI.WindowTitle = " ************    " + $bittitle + $username + "    " + $time + "    ************"
	Write-Host `n $bitHeader `n -ForegroundColor yellow

  function new-securepassword	
	{	
	$password = read-host -prompt "Enter your Password"
	$secure = ConvertTo-SecureString $password -force -asPlainText
	$bytes = ConvertFrom-SecureString $secure
	$bytes | out-file $Path
	}
	

