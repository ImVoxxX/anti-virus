using System.Text.Json;
using System.Text.Json.Serialization;

namespace PersonalAV.Core.Ipc;

/// <summary>
/// Wire format: one JSON object per line in each direction, UTF-8. A connection may carry several
/// request/response pairs.
/// </summary>
public static class PipeProtocol
{
    public const string PipeName = "PersonalAV.Control";

    /// <summary>Requests longer than this are rejected rather than parsed.</summary>
    public const int MaxRequestChars = 64 * 1024;

    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };
}

public static class Commands
{
    public const string StartScan = "StartScan";
    public const string CancelScan = "CancelScan";
    public const string GetStatus = "GetStatus";
    public const string ListDetections = "ListDetections";
    public const string ListQuarantine = "ListQuarantine";
    public const string Restore = "Restore";
    public const string Delete = "Delete";
    public const string ReloadRules = "ReloadRules";
    public const string ImportHashes = "ImportHashes";
    public const string GetEngineInfo = "GetEngineInfo";
}

/// <param name="Command">One of <see cref="Commands"/>.</param>
/// <param name="Kind">StartScan: quick, full or path.</param>
/// <param name="Path">StartScan (path kind) and ImportHashes: a file or folder.</param>
/// <param name="Id">Restore and Delete: a quarantine entry id.</param>
/// <param name="Limit">ListDetections: maximum rows.</param>
/// <param name="Overwrite">Restore: replace a file already at the original path.</param>
public sealed record PipeRequest(
    string Command,
    ScanKind? Kind = null,
    string? Path = null,
    string? Id = null,
    int? Limit = null,
    bool? Overwrite = null);

public sealed record PipeResponse(bool Ok, string? Error = null, JsonElement? Data = null)
{
    public static PipeResponse Success(object? data = null) =>
        new(true, Data: data is null ? null : JsonSerializer.SerializeToElement(data, data.GetType(), PipeProtocol.Json));

    public static PipeResponse Failure(string error) => new(false, error);

    public T? DataAs<T>() => Data is { } element ? element.Deserialize<T>(PipeProtocol.Json) : default;
}
