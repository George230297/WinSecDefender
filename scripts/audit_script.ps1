# Este script devuelve un objeto JSON para ser leído por Python
$ErrorActionPreference = 'Stop'
$results = @{}

try {
    # 1. Verificar SMBv1 (Riesgo Crítico)
    # Usamos Get-WindowsOptionalFeature si está disponible, sino, WMI/CIM fallback
    $smbStatus = "Unknown"
    if (Get-Command "Get-WindowsOptionalFeature" -ErrorAction SilentlyContinue) {
        $feat = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
        $smbStatus = if ($feat) { $feat.State } else { "Unknown" }
    } else {
        # Fallback check registry
        $reg = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -ErrorAction SilentlyContinue
        $smbStatus = if ($reg -and $reg.SMB1 -eq 0) { "Disabled" } else { "Likely Enabled" }
    }
    $results["SMBv1_Status"] = $smbStatus

    # 2. Verificar "Unquoted Service Paths" (Modernized with CIM)
    $unquotedServices = Get-CimInstance -ClassName Win32_Service | Where-Object {
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

    # Output limpio solo JSON
    $json = $results | ConvertTo-Json -Depth 2 -Compress
    Write-Output $json

} catch {
    # En caso de error fatal, devolvemos un JSON de error
    $err = @{ error = $_.Exception.Message }
    $err | ConvertTo-Json -Compress
}