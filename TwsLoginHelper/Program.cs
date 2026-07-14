namespace TwsLoginHelperHost;

using System;
using System.CommandLine;
using System.CommandLine.Invocation;

internal class Program
{
#if true
    static FakeConsoleWindow console;

    public static void Main(string[] args)
    {
        JavaAccessBridge.Initialize();

        Program.console = new FakeConsoleWindow("TWS Login Helper");

        var vaultIdOption = new Option<Guid>("--vault-id") { Description = "Bitwarden Vault ID", Required = true };

        var loginCommand = new Command("--login", "Perform login immediately and exit")
        {
            vaultIdOption
        };
        loginCommand.Validators.Add((result) =>
        {
            if (result.GetValue(vaultIdOption) == default)
            {
                result.AddError("--vault-id is required for --login");
            }
        });
        loginCommand.SetAction((result) =>
        {
            var vaultId = result.GetRequiredValue(vaultIdOption);

            var twsHelper = new TwsLoginHelper(new LoginProvider(vaultId));

            twsHelper.Login();
        });

        var rootCommand = new RootCommand("TWS Login Helper")
        {
            vaultIdOption,
            loginCommand
        };
        rootCommand.Validators.Add((result) =>
        {
            if (result.GetValue(vaultIdOption) == default)
            {
                result.AddError("--vault-id is required");
            }
        });
        rootCommand.SetAction((result) =>
        {
            var vaultId = result.GetRequiredValue(vaultIdOption);

            var twsHelper = new TwsLoginHelper(new LoginProvider(vaultId));

            twsHelper.Run();
        });

        var result = rootCommand.Parse(args);

        result.Invoke();
    }
#else
    public static async Task Main(string[] args)
    {
        var vault = new BitwardenVault();

        vault.Unlock();

        var login = vault.GetItem(args[0]);

        var username = vault.GetLoginProperty(login, "username");
        var password = vault.GetLoginProperty(login, "password");
        var totp = vault.GenerateTotp(login);
    }
#endif
}
