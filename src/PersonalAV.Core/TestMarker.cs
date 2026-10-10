namespace PersonalAV.Core;

/// <summary>
/// A harmless string matched by rules/personalav_test.yar, for testing detection without EICAR
/// (which Defender removes first). It is assembled at runtime so this project's own binaries never
/// contain it and never match the rule.
/// </summary>
public static class TestMarker
{
    public static string Value { get; } = new string("6202-ERUTANGIS-TSET-SSELMRAH-VALANOSREP".Reverse().ToArray());
}
