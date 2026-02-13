using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

public class AdminRole
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();
    
    [Required]
    public string Name { get; set; } = "";
    
    // Liste des permissions séparées par des virgules (ex: "products.read,products.write,audit.view")
    public string Permissions { get; set; } = "";
    
    public ICollection<AdminUser> Users { get; set; } = new List<AdminUser>();
}

public class AdminUser
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();
    
    [Required]
    public string Username { get; set; } = "";
    
    [Required]
    public string Email { get; set; } = "";
    
    [Required]
    public string PasswordHash { get; set; } = "";
    
    public bool MustChangePassword { get; set; } = true;
    
    public bool IsEnabled { get; set; } = true;
    
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    
    [Required]
    public Guid RoleId { get; set; }
    public AdminRole? Role { get; set; }
}
