# LockOn Decryptor

If you have watched  [Envoye Special](https://www.youtube.com/watch?v=JrFoFBNfv7A) on 14-DEC-2017, you might have noticed the following piece of ransomware used: [5691844cacd14051ddd92ae5e50b13cf](https://www.virustotal.com/#/file/a65bf23405e3f74015ee5215c3cafcb1d73d7cd7939c8f50dd73c6ca00f30c3c/detection).

This malware is non-functional (merely a test) ; it will only encrypt files under `C:\testrw`.

Nevertheless here is a decryption tool that might become handy:
1. Checkout `Program.cs`
2. Compile with `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe Program.cs` (requires .NET Framework 4.0).
3. Locate `windowsdefender.bin` master key file (usually located in `%TEMP%`).
4. Decrypt individual files, e.g. `Program.exe encrypted.lockon`.

PS. There is another weakness in the software, but this one was the most straightforward to exploit.
