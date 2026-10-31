# SPDX-License-Identifier: Apache-2.0
# Copyright (c) Alingan Patra
#
# Renders the user guide (docs/guide/*.md) and the install guides to
# standalone HTML in build/guide/, for shipping in every archive and package.
# Uses `pandoc` when installed, else the pandoc/core container.
#
# Usage: pwsh scripts/render-guide.ps1
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)

$out = 'build/guide'
if (Test-Path $out) { Remove-Item -Recurse -Force $out }
New-Item -ItemType Directory -Force "$out/install" | Out-Null
Copy-Item packaging/branding/wedge-logo.svg $out
Copy-Item packaging/branding/wedge-logo.svg "$out/install"

$css = @'
body{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;max-width:52rem;margin:2rem auto;padding:0 1rem;line-height:1.55;color:#0B1F3A}
a{color:#0369A1}code,pre{font-family:ui-monospace,Consolas,monospace;font-size:.92em}
pre{background:#F1F5F9;padding:.8rem 1rem;overflow-x:auto;border-radius:6px}
table{border-collapse:collapse;width:100%}th,td{border:1px solid #CBD5E1;padding:.35rem .6rem;text-align:left;vertical-align:top}
th{background:#E2E8F0}blockquote{border-left:4px solid #0EA5E9;margin-left:0;padding-left:1rem;color:#334155}
'@
[IO.File]::WriteAllText((Join-Path $PWD "$out/style.css"), $css)
Copy-Item "$out/style.css" "$out/install"

$usePandoc = [bool](Get-Command pandoc -ErrorAction SilentlyContinue)
function Convert-Page([string]$source, [string]$target, [string]$cssPath) {
    $text = (Get-Content $source -Raw) -replace "`r`n", "`n"
    # Links between pages point at the HTML versions; the logo sits beside them.
    $text = [regex]::Replace($text, '\]\(([^)#:]+)\.md(#[^)]*)?\)', ']($1.html$2)')
    $text = $text.Replace('../../packaging/branding/wedge-logo.svg', 'wedge-logo.svg')
    $title = ([regex]::Match($text, '(?m)^# (.+)$')).Groups[1].Value
    $tmp = [IO.Path]::ChangeExtension($target, '.src.md')
    [IO.File]::WriteAllText((Join-Path $PWD $tmp), $text)
    $pandocArgs = @('--standalone', '--from', 'gfm', '--to', 'html5', '--css', $cssPath,
        '--metadata', "title=$title", '--output', $target, $tmp)
    if ($usePandoc) {
        & pandoc @pandocArgs
    } else {
        docker run --rm -v "${PWD}:/data" -w /data pandoc/core:3.5 @pandocArgs
    }
    if ($LASTEXITCODE -ne 0) { throw "pandoc failed on $source" }
    Remove-Item $tmp
}

foreach ($page in Get-ChildItem docs/guide -Filter *.md) {
    $name = if ($page.BaseName -eq 'README') { 'index' } else { $page.BaseName }
    Convert-Page $page.FullName "$out/$name.html" 'style.css'
}
foreach ($page in Get-ChildItem docs/install -Filter *.md) {
    $name = if ($page.BaseName -eq 'README') { 'index' } else { $page.BaseName }
    Convert-Page $page.FullName "$out/install/$name.html" 'style.css'
}
# Links that left the guide folder now point inside the rendered copy.
foreach ($file in Get-ChildItem $out -Recurse -Filter *.html) {
    $html = Get-Content $file.FullName -Raw
    $html = $html.Replace('href="../install/README.html"', 'href="install/index.html"')
    $html = $html.Replace('href="../install/', 'href="install/').Replace('href="README.html"', 'href="index.html"')
    $html = $html.Replace('href="../guide/', 'href="../')
    # Pages that are not rendered here (architecture, security records) open
    # on GitHub.
    $repo = 'https://github.com/alinganpatra20004/wedge/blob/main'
    $html = [regex]::Replace($html, 'href="(?:\.\./)+(architecture|security)/([^"#]+)\.html',
        { param($m) "href=`"$repo/docs/$($m.Groups[1].Value)/$($m.Groups[2].Value).md" })
    $html = [regex]::Replace($html, 'href="(?:\.\./)+SECURITY\.html', "href=`"$repo/SECURITY.md")
    [IO.File]::WriteAllText($file.FullName, $html)
}
Write-Host "rendered $((Get-ChildItem $out -Recurse -Filter *.html).Count) pages to $out"
