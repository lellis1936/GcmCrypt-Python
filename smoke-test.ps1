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

Write-Host "Python/C# interoperability smoke test passed."
