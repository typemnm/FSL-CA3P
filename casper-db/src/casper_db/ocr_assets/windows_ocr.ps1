$ErrorActionPreference = 'Stop'
[Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

try {
    Add-Type -AssemblyName System.Runtime.WindowsRuntime
    $null = [Windows.Media.Ocr.OcrEngine,Windows.Foundation,ContentType=WindowsRuntime]
    $null = [Windows.Globalization.Language,Windows.Globalization,ContentType=WindowsRuntime]
    $request = [Console]::In.ReadToEnd() | ConvertFrom-Json
    $languages = @([Windows.Media.Ocr.OcrEngine]::AvailableRecognizerLanguages | ForEach-Object { $_.LanguageTag })
    if ($request.action -eq 'status') {
        @{engine='windows-media-ocr'; languages=$languages; confidence_supported=$false;
          max_dimension=[Windows.Media.Ocr.OcrEngine]::MaxImageDimension} | ConvertTo-Json -Compress
        exit 0
    }
    $language = [Windows.Globalization.Language]::new([string]$request.language)
    $engine = [Windows.Media.Ocr.OcrEngine]::TryCreateFromLanguage($language)
    if ($null -eq $engine) { throw 'Requested OCR language is not installed locally' }
    $null = [Windows.Storage.StorageFile,Windows.Storage,ContentType=WindowsRuntime]
    $null = [Windows.Storage.Streams.IRandomAccessStream,Windows.Storage.Streams,ContentType=WindowsRuntime]
    $null = [Windows.Graphics.Imaging.BitmapDecoder,Windows.Foundation,ContentType=WindowsRuntime]
    $null = [Windows.Graphics.Imaging.SoftwareBitmap,Windows.Foundation,ContentType=WindowsRuntime]
    $null = [Windows.Media.Ocr.OcrResult,Windows.Foundation,ContentType=WindowsRuntime]
    $asTask = [System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
        $_.Name -eq 'AsTask' -and $_.IsGenericMethod -and $_.GetGenericArguments().Count -eq 1 -and
        $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'
    } | Select-Object -First 1
    function Await-Result($operation, $resultType) {
        $task = $asTask.MakeGenericMethod($resultType).Invoke($null, @($operation))
        $task.GetAwaiter().GetResult()
    }
    $file = Await-Result ([Windows.Storage.StorageFile]::GetFileFromPathAsync([string]$request.path)) ([Windows.Storage.StorageFile])
    $stream = Await-Result ($file.OpenAsync([Windows.Storage.FileAccessMode]::Read)) ([Windows.Storage.Streams.IRandomAccessStream])
    try {
        $decoder = Await-Result ([Windows.Graphics.Imaging.BitmapDecoder]::CreateAsync($stream)) ([Windows.Graphics.Imaging.BitmapDecoder])
        $width = [int64]$decoder.PixelWidth
        $height = [int64]$decoder.PixelHeight
        $limit = [Windows.Media.Ocr.OcrEngine]::MaxImageDimension
        if ($width -le 0 -or $height -le 0 -or $width -gt $limit -or $height -gt $limit -or $width*$height -gt 8000000) {
            throw 'Image dimensions exceed local OCR limits'
        }
        $decoded = Await-Result ($decoder.GetSoftwareBitmapAsync()) ([Windows.Graphics.Imaging.SoftwareBitmap])
        try {
            $bitmap = [Windows.Graphics.Imaging.SoftwareBitmap]::Convert($decoded, [Windows.Graphics.Imaging.BitmapPixelFormat]::Gray8)
            try {
                $result = Await-Result ($engine.RecognizeAsync($bitmap)) ([Windows.Media.Ocr.OcrResult])
                $lines = @($result.Lines | ForEach-Object {
                    $line = $_
                    $words = @($line.Words | ForEach-Object {
                        $rect = $_.BoundingRect
                        @{text=$_.Text; box=@{x=$rect.X;y=$rect.Y;width=$rect.Width;height=$rect.Height}}
                    })
                    @{text=$line.Text; words=$words}
                })
                @{engine='windows-media-ocr'; language=$engine.RecognizerLanguage.LanguageTag;
                  width=$width; height=$height; text=$result.Text; lines=$lines;
                  text_angle=$result.TextAngle; confidence=$null;
                  pixel_conversion='Gray8; original image bytes unchanged'} | ConvertTo-Json -Depth 10 -Compress
            } finally { $bitmap.Dispose() }
        } finally { $decoded.Dispose() }
    } finally { $stream.Dispose() }
} catch {
    @{error='local_ocr_failed'; message=$_.Exception.Message} | ConvertTo-Json -Compress
    exit 2
}
