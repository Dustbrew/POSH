
module dbfunctions







# See if 32 or 64 --------------------------------------------------------------------------------------------------
if ($env:Processor_Architecture -ne 'x86'){
# 64 bit processes here

#notepad+ 64Bit


	
function np($file)
{
  if ($file -eq $null)
    {
        & 'C:\Program Files (x86)\Notepad++\notepad++.exe';
    }
    else
    {
        & 'C:\Program Files (x86)\Notepad++\notepad++.exe' $file;
    }		
}

}

#-----
else 
{

function np($file)
{
  if ($file -eq $null)
    {
        & 'C:\Program Files\Notepad++\notepad++.exe';
    }
    else
    {
        & 'C:\Program Files\Notepad++\notepad++.exe' $file;
    }	
}

}


function Start-Start
{
    & "start" .
}





function tran {

## Transcript

#Write-Verbose ("[{0}] Initialize Transcript" -f (Get-Date).ToString()) -Verbose

If ($host.Name -eq "ConsoleHost") {

    $transcripts =   "C:\admin\logs\transcripts"

    If (-Not (Test-Path $transcripts)) {

            New-Item -path $transcripts -Type Directory | out-null

            }

    $global:TRANSCRIPT = ("{0}\PSLOG_{1:dd-MM-yyyy}.txt" -f $transcripts,(Get-Date))

    Start-Transcript -Path $transcript -Append

    Get-ChildItem $transcripts | Where {

        $_.LastWriteTime -lt (Get-Date).AddDays(-14)

    } | Remove-Item -Force -ea 0

}
}




Function Get-QOTD 
{
<#
.Synopsis
Download quote of the day.
.Description
Using Invoke-RestMethod download the quote of the day from the BrainyQuote RSS
feed. The URL parameter has the necessary default value.
.Example
PS C:\> get-qotd
"We choose our joys and sorrows long before we experience them." - Khalil Gibran
.Link
Invoke-RestMethod
#>
    [cmdletBinding()]

    Param(
    [Parameter(Position=0)]
    [ValidateNotNullorEmpty()]
    [string]$Url="http://feeds.feedburner.com/brainyquote/QUOTEBR"
    )

    Write-Verbose "$(Get-Date) Starting Get-QOTD" 
    Write-Verbose "$(Get-Date) Connecting to $url"

    Try
    {
        #retrieve the url using Invoke-RestMethod
        Write-Verbose "$(Get-Date) Running Invoke-Restmethod"
       
        #if there is an exception, store it in my own variable.
        $data = Invoke-RestMethod -Uri $url -ErrorAction Stop -ErrorVariable myErr

        #The first quote will be the most recent
        Write-Verbose "$(Get-Date) retrieved data"
        $quote = $data[0]
    }
    Catch
    {
        $msg = "There was an error connecting to $url. "
        $msg += "$($myErr.Message)."

        Write-Warning $msg
    }

    #only process if we got a valid quote response
    if ($quote.description)
    {
        Write-Verbose "$(Get-Date) Processing $($quote.OrigLink)"
        #write a quote string to the pipeline
        "{0} - {1}" -f $quote.Description,$quote.Title
    }
    else
    {
        Write-Warning "Failed to get expected QOTD data from $url."
    }

    Write-Verbose "$(Get-Date) Ending Get-QOTD"

} #end Get-QOTD






Function Contacts 
{
Import-Csv C:\admin\dat\Contacts.csv | Select-Object "name","Mobile Phone", "Home Phone" 
}


function note()
{
Do 
{
Clear-host
 Write-Host "
 ----------  Add to note  ---------- 
 1 = Journal
 2 = I.T.
 3 = Fixes
 4 = Tech
 5 = Quotes
 6 = Jokes
 7 = Facts
 8 = Symbols
 9 = Temp
 "-Foregroundcolor yellow

$choice1 = read-host -prompt "Select number & press enter" 
} until ($choice1 -eq "1" -or $choice1 -eq "2" -or $choice1 -eq "3" -or $choice1 -eq "4" -or $choice1 -eq "5" -or $choice1 -eq "6" -or $choice1 -eq "7" -or $choice1 -eq "8" -or $choice1 -eq "9") 
 clear-host
Switch ($choice1) 
{
"1" { $Note = "C:\Admin\Logs\Journal.txt" } 
"2" { $Note = "C:\Admin\Notes\IT.txt"} 
"3" { $Note = "C:\Admin\Notes\fixes.txt"}
"4" { $Note = "C:\Admin\Notes\tech.txt"}
"5" { $Note = "C:\Admin\Notes\quotes.txt"}
"6" { $Note = "C:\Admin\Notes\jokes.txt"}
"7" { $Note = "C:\Admin\Notes\facts.txt"}
"8" { $Note = "C:\Admin\Notes\symbols.txt"}
"9" { $Note = "C:\Admin\Notes\temp.txt"}
}
Do 
{
Clear-host
 Write-Host "
 ----------  Add to note  ---------- 
 1 = Insert to file
 2 = Open File
 "-Foregroundcolor yellow

$choice1 = read-host -prompt "Select number & press enter" 
} until ($choice1 -eq "1" -or $choice1 -eq "2") 
 clear-host
Switch ($choice1) {
"1" { 
$Sep = " _______________________________________________ `n "
cls
write-host "->" -NoNewLine;
$msg = read-host;
#$sep | out-file $note  -append -force
Get-Date -format g | out-file $note  -append -force
$msg | out-file $note  -append -force

 } 
"2" { np $note}

}
}


Function colors {
#[system.consolecolor]::GetNames("consolecolor")
write-host "Black" -foregroundcolor Black
write-host "Blue" -foregroundcolor Blue
write-host "Cyan" -foregroundcolor Cyan
write-host "DarkBlue" -foregroundcolor DarkBlue
write-host "DarkCyan" -foregroundcolor DarkCyan
write-host "DarkGray" -foregroundcolor DarkGray
write-host "DarkGreen" -foregroundcolor DarkGreen
write-host "DarkMagenta" -foregroundcolor DarkMagenta
write-host "DarkRed" -foregroundcolor DarkRed
write-host "DarkYellow" -foregroundcolor DarkYellow
write-host "Gray"  -foregroundcolor Gray
write-host "Green" -foregroundcolor Green
write-host "Magenta" -foregroundcolor Magenta
write-host "Red" -foregroundcolor Red
write-host "White" -foregroundcolor White
write-host "Yellow" -foregroundcolor Yellow
}


function write-chost($message = ""){
    [string]$pipedMessage = @($Input)
    if (!$message)
    {  
        if ( $pipedMessage ) {
            $message = $pipedMessage
        }
    }
	if ( $message ){
		# predefined Color Array
		$colors = @("black","blue","cyan","darkblue","darkcyan","darkgray","darkgreen","darkmagenta","darkred","darkyellow","gray","green","magenta","red","white","yellow");

		# Get the default Foreground Color
		$defaultFGColor = $host.UI.RawUI.ForegroundColor

		# Set CurrentColor to default Foreground Color
		$CurrentColor = $defaultFGColor

		# Split Messages
		$message = $message.split("#")

		# Iterate through splitted array
		foreach( $string in $message ){
			# If a string between #-Tags is equal to any predefined color, and is equal to the defaultcolor: set current color
			if ( $colors -contains $string.tolower() -and $CurrentColor -eq $defaultFGColor ){
				$CurrentColor = $string          
			}else{
				# If string is a output message, than write string with current color (with no line break)
				write-host -nonewline -f $CurrentColor $string
				# Reset current color
				$CurrentColor = $defaultFGColor
			}
			# Write Empty String at the End
		}
		# Single write-host for the final line break
		write-host
	}
}











function ff($file)
{
  if ($file -eq $null)
    {
        Start-Process "firefox.exe"
    }
    else
    {
       Start-Process "firefox.exe" $file;
    }	
}

function all {
		  Clear-host
		 
		 
		 
		  Write-host $bitHeader  -Foregroundcolor yellow
		 
         
		 Write-host -
          Write-host  (Get-Date -Format D) -Foregroundcolor yellow
		  Write-host  (Get-Date -Format T) -Foregroundcolor yellow
		   Write-host (Get-country) -Foregroundcolor yellow
          Write-host -		  
		  Write-host
		  Write-host (user) -Foregroundcolor yellow
	      Write-host  "Is Admin? "  -Foregroundcolor yellow -nonewline
		  Write-host  (Test-IsAdmin) 
		  
		  Write-host 
		  Write-host -
		
		  Write-host "External IP"(ipx) -Foregroundcolor yellow
          Write-host "Local IP:  "(ipl) -Foregroundcolor yellow	
		  Write-host "Gateway:   " (Gateway) -Foregroundcolor yellow
		  Write-host
		  Write-host -
          Write-Host (Get-Uptime) -Foregroundcolor green -nonewline
          Write-Host "Lastboot:  "(get-lastboot) -Foregroundcolor green
		  Write-host
		  Write-host -
          Write-host "CPU Information" -Foregroundcolor yellow -nonewline
		  cpu
		  Write-host -
		  Write-host "Memory" -Foregroundcolor yellow 
		  mem
		  Write-host -
		  Write-host 
		  os $server
		  #Write-Host "`n`n" 
		  #Write-host "Appears this shit's working... `n`n`n"
		  
		 
		  }
		  
#end all



function MOD 
{
$mod = dir C:\ADMIN\SCRIPTS\mymodules | get-module | foreach {"`r`nmodule name: $_"; "`r`n";gcm -Module $_.name -CommandType cmdlet, function | select name} 


}



 function ClipHistory { (Get-History).CommandLine | clip }

 Function ld    { Get-Childitem -Attributes D }

 Function lf    { Get-Childitem -File }

 Function lsp   { Get-Childitem | More }



function myfun {
$sysfunctions = gci function:
gci function: | where {$sysfunctions -notcontains $_} 
}

# LIST FUNCTIONS
function fun
{
Get-ChildItem function:\
}


# EDIT Functions
Function fu
{
np c:\admin\dat\PS_All.npz
}


function Get-Verb {
[psobject].assembly.getexportedtypes() | `
? {$_.name -like "Verbs*"} | gm -static -membertype property | `
sort Name | select Name
}


# Show all available aliase
function Show-Alias() {
	Get-Help * | ?{$_.Category -eq "Alias"} | sort Name | Format-Table -auto
}


# Show all available contextual help
function Show-About() {
	Get-Help About_ | select name,synopsis | format-table -auto
}





function Get-Var
{
    $builtin = [powershell]::create().addcommand('Get-Variable').invoke() | Select-Object -ExpandProperty Name
    $builtin += 'args','MyInvocation','profile', 'PSBoundParameters', 'PSCommandPath', 'psISE', 'PSScriptRoot', 'psUnsupportedConsoleApplications'

    Get-Variable |
      Where-Object { $builtin -NotContains $_.Name } |
      Select-Object -Property Name, Value, Description
}



function Get-foldersize 
 {

 
 $dir = read-host -prompt "enter directory"

 
 $colItems = (Get-ChildItem $dir -recurse | Measure-Object -property length -sum)
"{0:N2}" -f ($colItems.sum / 1MB) + " MB"




$colItems = (Get-ChildItem $dir -recurse | Measure-Object -property length -sum)
"$Dir -- " + "{0:N2}" -f ($colItems.sum / 1MB) + " MB"

$colItems = (Get-ChildItem $dir -recurse | Where-Object {$_.PSIsContainer -eq $True} | Sort-Object)
foreach ($i in $colItems)
    {
        $subFolderItems = (Get-ChildItem $i.FullName | Measure-Object -property length -sum)
        $i.FullName + " -- " + "{0:N2}" -f ($subFolderItems.sum / 1MB) + " MB"
    }
}




function Restart-Posh
{
    [CmdletBinding(
        SupportsShouldProcess,
        ConfirmImpact='low')] 
    Param
    (
        [switch]
        $AsAdmin,

        [switch]
        $Force
    )
    
    process
    {
        if ($Force -or $PSCmdlet.ShouldProcess($proc.Name, "Restart the console as administrator : '{0}'" -f $AsAdmin))    # comfirmation to restart
        {
            if (($host.Name -eq 'Windows PowerShell ISE Host') -and ($psISE.PowerShellTabs.Files.IsSaved -contains $false))        # ise detect and unsave tab check
            {
                if ($Force -or $PSCmdlet.ShouldProcess('Unsaved work detected?','Unsaved work detected. Save changes?','Confirm')) # ise tab save dialog
                {
                    # dialog selected yes.
                    $psISE.PowerShellTabs | Start-SaveAndCloseISETabs
                }
                else
                {
                    # dialog selected no.
                    $psISE.PowerShellTabs | Start-CloseISETabs
                }
            }

            #region restart host process
            Write-Debug ("Start new host : '{0}'" -f $proc.Name)
            Start-Process @params

            Write-Debug ("Close old host : '{0}'" -f $proc.Name)
            $proc.CloseMainWindow()
            #endregion
        }
    }

    begin
    {
        $proc = Get-Process -Id $PID
 
        #region Setup parameter for restart host
        $params = @{
            FilePath = $proc.Path
        }

        if ($AsAdmin)
        {
            $params.Verb = 'runas'
        }

        if ($cmdArgs)
        {
            $params.ArgumentList = [Environment]::GetCommandLineArgs() | Select-Object -Skip 1
        }
        #endregion

        #region internal function to close ise with save
        filter Start-SaveAndCloseISETabs
        {
            $_.Files `
            | % { 
                if($_.IsUntitled -and (-not $_.IsSaved))
                {
                    $_.SaveAs($_.FullPath, [System.Text.Encoding]::UTF8)
                }
                elseif(-not $_.IsSaved)
                {
                    $_.Save()
                }
            }
        }
        #endregion

        #region internal function to close ise without save
        filter Start-CloseISETabs
        {
            $ISETab = $_
            $unsavedFiles = $IseTab.Files | where IsSaved -eq $false
            $unsavedFiles | % {$IseTab.Files.Remove($_,$true)}
        }
        #endregion
    }
}








Function ref
{
Get-Module | Remove-Module
    @(
        $Profile.AllUsersAllHosts,
        $Profile.AllUsersCurrentHost,
        $Profile.CurrentUserAllHosts,
        $Profile.CurrentUserCurrentHost
    ) | % {
        if(Test-Path $_) {
            Write-Verbose "Running $_"
            . $_
        }
    }    
}



function Get-Accelerators
{
[psobject].Assembly.GetType("System.Management.Automation.TypeAccelerators")::get
}



function Test-DatePattern
{
#http://jdhitsolutions.com/blog/2014/10/powershell-dates-times-and-formats/
$patterns = "d","D","g","G","f","F","m","o","r","s", "t","T","u","U","Y","dd","MM","yyyy","yy","hh","mm","ss","yyyyMMdd","yyyyMMddhhmm","yyyyMMddhhmmss"
Write-host "It is now $(Get-Date)" -ForegroundColor Green
foreach ($pattern in $patterns) {
#create an Object
[pscustomobject]@{
Pattern = $pattern
Syntax = "Get-Date -format '$pattern'"
Value = (Get-Date -Format $pattern)
}
} #foreach
Write-Host "Most patterns are case sensitive" -ForegroundColor Green
}





function Calendar {
  <#
    .SYNOPSIS
    Displays a calendar.
    
    .DESCRIPTION
    Displays a simple calendar with today's date highlighted.
    
    .EXAMPLE
    PS> Get-Calendar
    
        August 2013     
    Su Mo Tu We Th Fr Sa
                 1  2  3
     4  5  6  7  8  9 10
    11 12 13 14 15 16 17
    18 19 20 21 22 23 24
    25 26 27 28 29 30 31
    
  #>

  $today = Get-Date
  $first = Get-Date -Year $today.Year -Month $today.Month -Day 1
  $days = [datetime]::DaysInMonth($today.Year, $today.Month)
  
  $header = "{0:MMMM yyyy}" -f $today
  $header_padding = [math]::Floor((19 - $header.Length) / 2) + $header.Length
  $first_padding = 3 * [int]$first.DayOfweek
  
  Write-Host ""
  Write-Host ("{0,$header_padding}" -f $header)
  Write-Host "Su Mo Tu We Th Fr Sa"
  Write-Host ("{0,$first_padding}" -f "") -NoNewLine
  
  1..$days | %{ 
    $current = Get-Date -Year $today.Year -Month $today.Month -Day $_
    
    $date = @{$true=" $_ ";$false="$_ "}[$_ -lt 10]
    $foreground = @{$true="Green";$false=$HOST.UI.RawUI.ForegroundColor}[$_ -eq $today.Day]
    
    Write-Host $date -ForegroundColor $foreground -NoNewLine 
    
    if($current.DayOfWeek -eq "Saturday") { 
      Write-Host "" 
    }
  }
  
  Write-Host ""
  Write-Host ""
}





function stop-nonresponsive 
{
$notresponding = Get-Process   | Where-Object { $_.responding -eq $false} 
$notresponding.Kill() 
}











function hdinfo ($comp)
{
Get-RemoteDiskInformation -ComputerName $comp -Credential $cred
}

#--------------------------------------------------------------------------







function Grant-ElevatedProcess
{
<#
.SYNOPSIS
Runs a process as administrator. Stolen from http://weestro.blogspot.com/2009/08/sudo-for-powershell.html.
#>
$file, [string]$arguments = $args
$psi = New-Object System.Diagnostics.ProcessStartInfo $file
$psi.Arguments = $arguments
$psi.Verb = "runas"
$psi.WorkingDirectory = Get-Location
[System.Diagnostics.Process]::Start($psi) | Out-Null
}


function Test-IsAdmin
{
(new-object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole('Administrators');
}





Function user()
{
<#	.SYNOPSIS
Custom prompt
.DESCRIPTION
[USER]@[HOST] [PATH]>
#>
$identity = [Security.Principal.WindowsIdentity]::GetCurrent( )
$principal = [Security.Principal.WindowsPrincipal] $identity
if( $principal.IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator") )
{ $usercolor = "Green" }
else
{ $usercolor = "red" }
$location = Get-Location
if( $location.Path.Length -gt 30 )
{ $location = "...\$($location.Path.Split("\").Get( $location.Path.Split("\").count-1 ))"	}
Write-Host -NoNewLine -ForegroundColor $usercolor "$Env:USERNAME"
Write-Host -NoNewLine -ForegroundColor Gray "@"
Write-Host -NoNewLine -ForegroundColor Green "$Env:COMPUTERNAME "
#Write-Host -NoNewLine -ForegroundColor Gray $location
if (test-path variable:/PSDebugContext)
{ Write-Host -NoNewLine '[DBG]: ' }
if($NestedPromptLevel -ge 1)
{ Write-Host -NoNewLine '>>' }
Write-Host -NoNewLine '>'
return " "
}


function historyx {
get-history | out-gridview -Passthru | invoke-history
}






if (!(Test-Path alias:pipelist)) { Set-Alias pipelist Get-PipeList }

function Get-PipeList {
  <#
    .SYNOPSIS
        Gets list of all open named pipes.
    .DESCRIPTION
        The quickest way to do it:
        PS C:\> [IO.Directory]::GetFiles(
        >> "\\.\pipe\"
        >> ) | % {-join$_[($_.IndexOf('\', 5) + 1)..$_.Length]}
        Actually, GetFiles method is based on calls of two
        system functions (FindFirstFile and FindNextFile) and
        this script shows how does it work in reality.
    .NOTES
        Author: greg zakharov
  #>
  
  begin {
    $asm = [AppDomain]::CurrentDomain.GetAssemblies() | ? {
      $_.ManifestModule.ScopeName.Equals('CommonLanguageRuntimeLibrary')
    }
    
    $SafeFindHandle = $asm.GetType('Microsoft.Win32.SafeHandles.SafeFindHandle')
    $Win32Native = $asm.GetType('Microsoft.Win32.Win32Native')
    
    $WIN32_FIND_DATA = $Win32Native.GetNestedType(
        'WIN32_FIND_DATA', [Reflection.BindingFlags]32
    )
    $FindFirstFile = $Win32Native.GetMethod(
        'FindFirstFile', [Reflection.BindingFlags]40,
        $null, @([String], $WIN32_FIND_DATA), $null
    )
    $FindNextFile = $Win32Native.GetMethod(
        'FindNextFile', [Reflection.BindingFlags]40,
        $null, @($SafeFindHandle, $WIN32_FIND_DATA), $null
    )
    
    $obj = $WIN32_FIND_DATA.GetConstructors()[0].Invoke($null)
    
    function Read-Field([String]$Field) {
      return [String]$WIN32_FIND_DATA.GetField($Field, [Reflection.BindingFlags]36).GetValue($obj)
    }
  }
  process {
    '{0, -40} {1, 14}' -f 'Pipe Name', 'Instances'
    '{0, -40} {1, 14}' -f '---------', '---------'
    
    $hndl = $FindFirstFile.Invoke($null, @('\\.\pipe\*', $obj))
    '{0, -40} {1, 14}' -f (Read-Field cFileName), (Read-Field nFileSizeLow)
    
    while ($FindNextFile.Invoke($null, @($hndl, $obj))) {
      '{0, -40} {1, 14}' -f (Read-Field cFileName), (Read-Field nFileSizeLow)
    }
    
    $hndl.Close()
  }
  end { '' }
}


function othermodules {
Import-Module C:\Users\Dustin\Documents\WindowsPowerShell\Modules\Pipeworks\Pipeworks.psm1
Import-Module C:\Users\Dustin\Documents\WindowsPowerShell\Modules\RoughDraft\RoughDraft.psm1
Import-Module C:\Users\Dustin\Documents\WindowsPowerShell\Modules\ShowUI\ShowUI.psm1
Import-Module C:\Users\Dustin\Documents\WindowsPowerShell\Modules\PSReadLine\PSReadLine.psm1
}






	
function new-securepassword	
{	
$password = read-host -prompt "Enter your Password"
$Path = read-host -prompt "Enter path to save"


$secure = ConvertTo-SecureString $password -force -asPlainText
$bytes = ConvertFrom-SecureString $secure
$bytes | out-file $Path
}
	
	

function Kee {

$encrypted = gc c:\admin\dat\keys\keepass32.txt
$KeyFile = "c:\admin\dat\keys\AES.key"
$password = ConvertTo-SecureString -string $encrypted -Key $key
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
$PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
&"C:\Program Files\KeePass Password Safe 2\Keepass.exe"  "c:\admin\dat\keys\dbkee4.kdbx" --pw:$PlainPassword
}



function unblock
{
$directory = read-host -prompt "enter directory"
write-host "unblocking $directory "
gci $directory | Unblock-File
}






function get-pin 
{
 



$pin = Get-Content "c:\admin\dat\keys\Pin.txt"
$KeyFile = "c:\admin\dat\keys\AES.key"
$password = ConvertTo-SecureString -string $pin -Key $key
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
$pina = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR) 
$pinb = read-host "PIN" -AsSecureString
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Pinb)
$pinb = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR) 

If ($pina -eq $pinb) {wh "true"}
else {wh "false"}
} 
  






function zoo {Write-Host "bar"}