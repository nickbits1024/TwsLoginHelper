using System;
using System.IO;
using System.Text;

public sealed class FakeConsoleWriter : TextWriter
{
    private readonly FakeConsoleWindow window;
    private readonly TextWriter original;

    public FakeConsoleWriter(FakeConsoleWindow window)
    {
        this.window = window;
        this.original = Console.Out;
    }

    public override Encoding Encoding => Encoding.UTF8;

    public override void Write(string value)
    {
        this.window.Write(value ?? "");
        this.original.Write(value);
    }

    public override void WriteLine(string value)
    {
        this.window.WriteLine(value ?? "");
        this.original.WriteLine(value);
    }
}
