$progressPreference = 'silentlyContinue'
$latestWingetMsixBundleUri = $(Invoke-RestMethod https://api.github.com/repos/microsoft/winget-cli/releases/latest).assets.browser_download_url | Where-Object {$_.EndsWith(".msixbundle")}
$latestWingetMsixBundle = $latestWingetMsixBundleUri.Split("/")[-1]
Write-Information "Downloading winget to artifacts directory..."
Invoke-WebRequest -Uri $latestWingetMsixBundleUri -OutFile "./$latestWingetMsixBundle"
Invoke-WebRequest -Uri https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx -OutFile Microsoft.VCLibs.x64.14.00.Desktop.appx
Add-AppxPackage Microsoft.VCLibs.x64.14.00.Desktop.appx
Add-AppxPackage $latestWingetMsixBundle

# List of applications to install
$apps = @(
"7zip.7zip",
"IObit.Uninstaller",
"nilesoft.shell", # Microsoft Shell Fix DropDown Menu
"9NFKC78BRS8W",   # Fury CTRL DDR4 LEDs
"CrystalRich.LockHunter",
"MiniTool.PartitionWizard.Free",
"HermannSchinagl.LinkShellExtension",
"OpenDesignAlliance.ODAFileConverter",
"Bitdefender.Bitdefender",
"SoftDeluxe.FreeDownloadManager",
"Flow-Launcher.Flow-Launcher",
"Glarysoft.GlaryUtilities",
"Nlitesoft.NTLite",
"Oracle.VirtualBox",
"BlueStacks.Bluestacks",
"Microsoft.WindowsTerminal.Preview",
"Microsoft.PowerShell.Preview",
"QL-Win.QuickLook",
"keyviz",
"9NH1P86H06CG", # Radiograph Hardware Info Monitortying
"REALiX.HWiNFO",
"Logitech.GHUB",
"9MSPC6MP8FM4", # Microsoft Whiteboard
"OBSProject.OBSStudio",
"VideoLAN.VLC",
"SMPlayer.SMPlayer",
"Audacity.Audacity",
"HulubuluSoftware.AdvancedRenamer",
"IrfanSkiljan.IrfanView",
"IrfanSkiljan.IrfanView.PlugIns",
"Mirillis.Action",
"Inkscape.Inkscape",
"9NBLGGH4TWWG", # PhotoScape X
"Canva.Canva",
"Zoom.Zoom",
"Discord.Discord",
"HandBrake.HandBrake",
"9NBLGGH5L9XT", # Instagram
"9WZDNCRFJ2WL", # Facebook
"Ubisoft.Connect",
"EpicGames.EpicGamesLauncher",
"Valve.Steam",
"ElectronicArts.EADesktop",
"Google.PlayGames.Beta",
"SomePythonThings.WingetUIStore",
"Crunchyroll.MasterofGarden"
)

# Loop through the list and install each application
foreach ($app in $apps) {
    Write-Host "Installing $app"
    winget install --id $app --accept-package-agreements --accept-source-agreements --silent
}