namespace ADApiService.Models
{
    public class AdSettings
    {
        public List<string> Domains { get; set; } = new();
        public List<string> GeneralAccessGroups { get; set; } = new();
        public List<string> HighPrivilegeGroups { get; set; } = new();
        public List<string> OptionalGroupsForHighPrivilege { get; set; } = new();
        public string AdminGroup { get; set; } = string.Empty;
    }
}

