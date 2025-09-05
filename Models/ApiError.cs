namespace ADApiService.Models;

/// <summary>
/// Represents a standardized API error response.
/// </summary>
public class ApiError
{
    /// <summary>
    /// A high-level, user-friendly error message.
    /// </summary>
    public string Message { get; }

    /// <summary>
    /// Optional, more detailed information about the error, intended for developers.
    /// </summary>
    public string? Detail { get; }

    /// <summary>
    /// Creates a new instance of the ApiError.
    /// </summary>
    /// <param name="message">The high-level error message.</param>
    /// <param name="detail">Optional detailed error information.</param>
    public ApiError(string message, string? detail = null)
    {
        Message = message;
        Detail = detail;
    }
}

