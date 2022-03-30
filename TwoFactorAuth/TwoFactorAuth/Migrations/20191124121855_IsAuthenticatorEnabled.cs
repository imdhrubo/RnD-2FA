using Microsoft.EntityFrameworkCore.Migrations;

namespace TwoFactorAuth.Migrations
{
    public partial class IsAuthenticatorEnabled : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "IsAuthenticatorEnabled",
                table: "AspNetUsers",
                nullable: false,
                defaultValue: false);
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "IsAuthenticatorEnabled",
                table: "AspNetUsers");
        }
    }
}
