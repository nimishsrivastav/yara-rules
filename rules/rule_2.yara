rule BlueHowl
{
    meta:
        author = "Nimish"
        description = "Blue Howl Hackers"
        date = "2024-08-06"
        version = "1.0"

    strings:
        $mz = { 4d 5a }
        $s1 = { 00 42 00 6C 00 75 00 65 00 20 00 48 00 6F 00 77 00 6C 00 }

    condition:
        ($mz at 0) and $s1
}
