$gettag = gc C:/Windows/Panther/unattend.xml | select -Index 53
$original_string = $gettag 
$result = [regex]::Match($original_string, '[^<ComputerName>]+(?=</ComputerName)').Value
