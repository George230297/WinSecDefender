# Este script devuelve un objeto JSON para ser leído por Python
$results = @{}

# 1. Verificar SMBv1 (Riesgo Crítico)
$smbCheck = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | Select-Object -ExpandProperty State
$results["SMBv1_Status"] = $smbCheck

# 2. Verificar "Unquoted Service Paths"
$unquotedServices = Get-WmiObject win32_service | Where-Object {
    $_.StartMode -eq 'Auto' -and 
    $_.PathName -notmatch '^"' -and 
    $_.PathName -notmatch '^C:\\Windows' -and 
    $_.PathName -match '\s'
} | Select-Object -ExpandProperty Name

if ($unquotedServices) {
    $results["Unquoted_Services"] = $unquotedServices
    $results["Unquoted_Risk"] = "HIGH"
} else {
    $results["Unquoted_Services"] = "None"
    $results["Unquoted_Risk"] = "Low"
}

# 3. Verificar Último Parche (HotFix)
$lastPatch = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
if ($lastPatch) {
    $results["Last_Patch_ID"] = $lastPatch.HotFixID
    $results["Last_Patch_Date"] = $lastPatch.InstalledOn
} else {
    $results["Last_Patch_ID"] = "NotFound"
}

$results | ConvertTo-Json