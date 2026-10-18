namespace LinuxDiscovery.Tests;

public class SshBannerTests
{
    [Fact]
    public void Parses_ubuntu_openssh_banner()
    {
        Assert.True(SshBanner.TryParse("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5", out SshBanner? b));
        Assert.Equal("2.0", b!.ProtocolVersion);
        Assert.Equal("OpenSSH_9.6p1", b.SoftwareVersion);
        Assert.Equal("Ubuntu-3ubuntu13.5", b.Comments);
    }

    [Theory]
    [InlineData("HTTP/1.1 400 Bad Request")]
    [InlineData("SSH-")]
    [InlineData("SSH-2.0-")]
    [InlineData("SSH-x.y-Foo")]
    [InlineData("SSH-2.0-Foo\u0001Bar")]
    [InlineData("")]
    public void Rejects_non_ssh_or_malformed(string line)
    {
        Assert.False(SshBanner.TryParse(line, out _));
    }

    [Fact]
    public void Rejects_overlong_lines()
    {
        Assert.False(SshBanner.TryParse("SSH-2.0-" + new string('a', 300), out _));
    }

    [Fact]
    public void Extract_requires_a_complete_line()
    {
        Assert.False(SshBanner.TryExtract("SSH-2.0-OpenSSH_9.6", out _));
        Assert.True(SshBanner.TryExtract("SSH-2.0-OpenSSH_9.6\r\n", out SshBanner? b));
        Assert.Equal("SSH-2.0-OpenSSH_9.6", b!.Raw);
    }

    [Fact]
    public void Extract_skips_pre_banner_lines()
    {
        Assert.True(SshBanner.TryExtract("Welcome\r\nSSH-2.0-dropbear_2022.83\r\n", out SshBanner? b));
        Assert.Equal("dropbear_2022.83", b!.SoftwareVersion);
    }
}
