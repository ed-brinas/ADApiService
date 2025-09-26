namespace KeyStone.Models;

/// <summary>
/// Represents a standardized API error response.
/// </summary>
public class ApiError
{
    /// <summary>
    /// A high-level summary of the error.
    /// </summary>
    public string Message { get; set; }

    /// <summary>
    /// Optional: a more detailed, technical explanation of the error.
    /// </summary>
    public string? Detail { get; set; }

    public ApiError(string message, string? detail = null)
    {
        Message = message;
        Detail = detail;
    }
}

