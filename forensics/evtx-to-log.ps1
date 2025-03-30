# Папка, где находятся файлы EVTX
$inputFolder = "C:\путь\к\папке"

# Папка, куда сохранять LOG файлы (изменить при необходимости)
$outputFolder = "C:\ConvertedLogs"

# Создаём папку, если её нет
New-Item -ItemType Directory -Path $outputFolder -Force

# Находим все файлы EVTX и конвертируем их в LOG
Get-ChildItem -Path $inputFolder -Recurse -Filter "*.evtx" | ForEach-Object {
    $logPath = "$outputFolder\$($_.BaseName).log"
    wevtutil qe $_.FullName /f:text > $logPath
    Write-Host "Файл $($_.FullName) -> $logPath"
}

Write-Host "Конвертация завершена!"
