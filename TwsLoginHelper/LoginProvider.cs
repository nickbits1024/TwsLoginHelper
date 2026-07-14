using System;
using System.Collections.Generic;
using System.Text;

namespace TwsLoginHelperHost;

internal class LoginProvider : ILoginProvider
{
    private string itemId;

    public LoginProvider(Guid itemId)
    {
        this.itemId = itemId.ToString();
    }

    public string VaultItemId => this.itemId;

    public LoginDetails GetLogin()
    {
        using BitwardenVault bitwardenVault = new BitwardenVault();
        try
        {
            bitwardenVault.Unlock();

            var login = bitwardenVault.GetItem(this.itemId);

            var username = bitwardenVault.GetLoginProperty(login, "username");
            var password = bitwardenVault.GetLoginProperty(login, "password");
            var totpSecret = bitwardenVault.GetLoginProperty(login, "totp");

            return new LoginDetails { Username = username, Password = password, TotpSecret = totpSecret };
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Bitwarden error: {ex}");
            return null;
        }
    }

    public string GetTotp(String totpSecret)
    {
        return BitwardenVault.GenerateTotp(totpSecret);
    }
}
