namespace LinuxDiscovery.Tests;

public class CandidateClassifierTests
{
    private static SshProbeResult Open(string banner) =>
        new(PortState.Open, TestData.Banner(banner), null);

    [Fact]
    public void Ssh_open_with_ping_blocked_is_still_a_candidate()
    {
        var host = TestData.Host("192.168.1.42", Open("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13"), new IcmpResult(false, null, 0));

        Candidate c = Assert.Single(CandidateClassifier.Classify(new[] { host }));

        Assert.Equal(EvidenceLevel.LinuxLikely, c.Level);
        Assert.Contains(c.Reasons, r => r.Contains("ping may be blocked"));
    }

    [Fact]
    public void Ping_ok_but_ssh_closed_is_not_a_candidate()
    {
        var host = TestData.Host("192.168.1.50", new SshProbeResult(PortState.Closed, null, "refused"), new IcmpResult(true, 64, 1));
        Assert.Empty(CandidateClassifier.Classify(new[] { host }));
    }

    [Fact]
    public void Open_port_without_ssh_banner_is_not_a_candidate()
    {
        var host = TestData.Host("192.168.0.9", new SshProbeResult(PortState.Open, null, "no banner"));
        Assert.Empty(CandidateClassifier.Classify(new[] { host }));
    }

    [Fact]
    public void Plain_openssh_banner_does_not_claim_linux()
    {
        var host = TestData.Host("192.168.0.20", Open("SSH-2.0-OpenSSH_9.6"));
        Candidate c = Assert.Single(CandidateClassifier.Classify(new[] { host }));
        Assert.Equal(EvidenceLevel.SshServer, c.Level);
        Assert.Contains("not confirmed", c.Summary);
    }

    [Fact]
    public void Unix_like_ttl_is_weak_evidence_only()
    {
        var host = TestData.Host("192.168.0.21", Open("SSH-2.0-OpenSSH_9.6"), new IcmpResult(true, 64, 1));
        Candidate c = Assert.Single(CandidateClassifier.Classify(new[] { host }));
        Assert.Equal(EvidenceLevel.SshServerUnixLikeTtl, c.Level);
    }

    [Fact]
    public void Multiple_servers_are_ranked_linux_likely_first()
    {
        var plain = TestData.Host("192.168.0.5", Open("SSH-2.0-OpenSSH_9.6"));
        var debian = TestData.Host("192.168.1.7", Open("SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3"));

        var result = CandidateClassifier.Classify(new[] { plain, debian });

        Assert.Equal(2, result.Count);
        Assert.Equal("192.168.1.7", result[0].Host.Address.ToString());
    }
}
