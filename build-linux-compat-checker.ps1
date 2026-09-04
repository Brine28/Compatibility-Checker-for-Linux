param(
    [ValidateSet('arm64','x64','x86')]
    [string]$Target = 'arm64'
)

$common = @('-O3','-std=c++20','linux_compat_checker_portable_v2.cpp',
            '-ladvapi32','-lsetupapi','-lwinhttp')

switch ($Target) {
    'arm64' { $compiler = 'aarch64-w64-mingw32-g++'; $output = 'linux_compat_checker_arm64.exe' }
    'x64'   { $compiler = 'x86_64-w64-mingw32-g++';   $output = 'linux_compat_checker_x64.exe' }
    'x86'   { $compiler = 'i686-w64-mingw32-g++';      $output = 'linux_compat_checker_x86.exe' }
}

& $compiler @common '-o' $output
if ($LASTEXITCODE -ne 0) {
    throw "Build failed for $Target (exit code $LASTEXITCODE)."
}

Write-Host "Built $output successfully."
