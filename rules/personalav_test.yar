// Matches the harmless marker written by "pav testfile <path>". Use it to test detection,
// quarantine and restore without involving EICAR, which Defender removes first.
// Written as hex so this rule file does not match itself.
rule PersonalAV_Test_Marker
{
    meta:
        description = "PersonalAV harmless test marker"
        severity = "test"
    strings:
        $marker = { 50 45 52 53 4F 4E 41 4C 41 56 2D 48 41 52 4D 4C 45 53 53 2D 54 45 53 54 2D 53 49 47 4E 41 54 55 52 45 2D 32 30 32 36 }
    condition:
        $marker
}
