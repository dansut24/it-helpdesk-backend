# Get the system model number
$systemModel = (Get-CimInstance -ClassName Win32_ComputerSystem).Model
# Use a switch statement to run different files based on the system model number
switch ($systemModel) {
   "Latitude 3460" {
       Start-Process "C:\path\to\your\file1.exe"
       Write-Output "Running file for MODEL_NUMBER_1"
   }
   "Latitude 3450" {
       Start-Process "C:\another\path\to\file2.exe"
       Write-Output "Running file for MODEL_NUMBER_2"
   }
   "Latitude 3420" {
       Start-Process "C:\Windows\Setup\DELLDrivers\Latitude-3420.exe /s /driveronly /l=C:\Temp\Drivers.log"
       Write-Host "Drivers for $systemmodel found. Starting install..." -f green
   }
   default {
       Write-Output "System model does not match any target model numbers. No drivers installing. Exiting"
   }
}

$processNames = @("Latitude-3540", "Latitude-3420", "Latitude-3450")  # Replace with the actual process names (without .exe)
while ($true) {
   # Initialize a flag to track if any process matches
   $processRunning = $false
   foreach ($processName in $processNames) {
       # Check if the process is running
       $process = Get-Process -Name $processName -ErrorAction SilentlyContinue
       if ($process) {
           $processRunning = $true
           break  # Exit the loop as soon as one matching process is found
       }
   }
   if ($processRunning) {
       Write-Host "Please wait. Drivers for $systemmodel now installing. Script will exit once completed. Checking again in 30 seconds..." -f Green
   } else {
       Write-Host "Exiting script." -f Red
       break
   }
   # Wait for 30 seconds before checking again
   Start-Sleep -Seconds 30
}
