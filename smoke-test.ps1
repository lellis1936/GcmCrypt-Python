param(
    [Parameter(Mandatory = $true)]
    [string]$CSharpExe
)

$ErrorActionPreference = "Stop"

function Assert-SameFile {
    param([string]$Expected, [string]$Actual)

    $expectedBytes = [System.IO.File]::ReadAllBytes($Expected)
    $actualBytes = [System.IO.File]::ReadAllBytes($Actual)
    if ($expectedBytes.Length -ne $actualBytes.Length) {
        throw "Length mismatch between $Expected and $Actual"
    }
    for ($i = 0; $i -lt $expectedBytes.Length; $i++) {
        if ($expectedBytes[$i] -ne $actualBytes[$i]) {
            throw "Byte mismatch at offset $i between $Expected and $Actual"
        }
    }
}

$repoRoot = $PSScriptRoot
$testDir = Join-Path $repoRoot "smoke-test-output"
if (Test-Path -LiteralPath $testDir) {
    $resolvedRepoRoot = (Resolve-Path -LiteralPath $repoRoot).Path
    $resolvedTestDir = (Resolve-Path -LiteralPath $testDir).Path
    if (!$resolvedTestDir.StartsWith($resolvedRepoRoot + [System.IO.Path]::DirectorySeparatorChar)) {
        throw "Refusing to remove test output outside the repository"
    }
    Remove-Item -LiteralPath $testDir -Recurse -Force
}
New-Item -ItemType Directory -Path $testDir | Out-Null

$python = (Get-Command python).Source
$pythonScript = Join-Path $repoRoot "gcmcrypt.py"
$password = "passw$([char]0x00F6)rd-$([char]0x6F22)$([char]0x5B57)"
$inputFile = Join-Path $testDir "input.bin"
$bytes = New-Object byte[] (3 * 64 * 1024 + 37)
for ($i = 0; $i -lt $bytes.Length; $i++) {
    $bytes[$i] = [byte]($i % 251)
}
[System.IO.File]::WriteAllBytes($inputFile, $bytes)

foreach ($compressed in @($false, $true)) {
    $suffix = if ($compressed) { "compressed" } else { "plain" }
    $pythonEncrypted = Join-Path $testDir "python-$suffix.gcm"
    $csharpDecrypted = Join-Path $testDir "csharp-from-python-$suffix.bin"
    $pythonArgs = @($pythonScript, "-e", "-f")
    if ($compressed) {
        $pythonArgs += "-compress"
    }
    $pythonArgs += @($password, $inputFile, $pythonEncrypted)
    & $python @pythonArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Python encryption failed"
    }
    & $CSharpExe -d -f $password $pythonEncrypted $csharpDecrypted
    if ($LASTEXITCODE -ne 0) {
        throw "C# decryption failed"
    }
    Assert-SameFile $inputFile $csharpDecrypted

    $csharpEncrypted = Join-Path $testDir "csharp-$suffix.gcm"
    $pythonDecrypted = Join-Path $testDir "python-from-csharp-$suffix.bin"
    $csharpArgs = @("-e", "-f")
    if ($compressed) {
        $csharpArgs += "-compress"
    }
    $csharpArgs += @($password, $inputFile, $csharpEncrypted)
    & $CSharpExe @csharpArgs
    if ($LASTEXITCODE -ne 0) {
        throw "C# encryption failed"
    }
    & $python $pythonScript -d -f $password $csharpEncrypted $pythonDecrypted
    if ($LASTEXITCODE -ne 0) {
        throw "Python decryption failed"
    }
    Assert-SameFile $inputFile $pythonDecrypted
}

$customIterations = 750000
$pythonCustomEncrypted = Join-Path $testDir "python-custom-iterations.gcm"
$csharpCustomDecrypted = Join-Path $testDir "csharp-from-python-custom-iterations.bin"
& $python $pythonScript -e -f -iter $customIterations $password $inputFile $pythonCustomEncrypted
if ($LASTEXITCODE -ne 0) {
    throw "Python custom-iteration encryption failed"
}
$pythonCustomBytes = [System.IO.File]::ReadAllBytes($pythonCustomEncrypted)
$iterationBytes = New-Object byte[] 4
[Array]::Copy($pythonCustomBytes, 82, $iterationBytes, 0, 4)
if ([BitConverter]::IsLittleEndian) {
    [Array]::Reverse($iterationBytes)
}
if ([BitConverter]::ToInt32($iterationBytes, 0) -ne $customIterations) {
    throw "Python did not write the custom PBKDF2 iteration count"
}
& $CSharpExe -d -f $password $pythonCustomEncrypted $csharpCustomDecrypted
if ($LASTEXITCODE -ne 0) {
    throw "C# custom-iteration decryption failed"
}
Assert-SameFile $inputFile $csharpCustomDecrypted

Write-Host "Python/C# interoperability smoke test passed."
