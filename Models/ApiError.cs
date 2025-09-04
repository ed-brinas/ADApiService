namespace ADApiService.Models
{
    /// <summary>
    /// Standardized error response for the API.
    /// </summary>
    public class ApiError
    {
        public string Message { get; set; }
        public string? Detail { get; set; }

        public ApiError(string message, string? detail = null)
        {
            Message = message;
            Detail = detail;
        }
    }
}

