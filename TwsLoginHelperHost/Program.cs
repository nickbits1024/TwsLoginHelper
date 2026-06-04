namespace TwsLoginHelperHost;

internal class Program
{
#if true
    public static void Main(string[] args) => TwsLoginHelper.Run(args, new LoginProvider(args[0]));
#else
    public static async Task Main(string[] args)
    {
        var vault = new BitwardenVault();

        vault.Unlock();

        var login = vault.GetItem(args[0]);
     
        var username = vault.GetLoginProperty(login, "username");
        var password = vault.GetLoginProperty(login, "password");
        var totp = vault.GetTotp(login);
    }
#endif
}
