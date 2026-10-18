namespace LinuxDiscovery.Tests;

public class ReachabilityPlannerTests
{
    private static SubnetPlan For(IReadOnlyList<SubnetPlan> plans, string cidr) => plans.Single(p => p.Subnet.Cidr == cidr);

    [Fact]
    public void Address_outside_all_subnets_needs_a_temporary_address_for_each()
    {
        var eth = TestData.Adapter("Ethernet", 1, new[] { "192.168.10.25/24" });
        var plans = ReachabilityPlanner.Plan(eth, new[] { eth });

        Assert.Equal(4, plans.Count);
        Assert.All(plans, p => Assert.Equal(SubnetAccess.NeedsTemporaryAddress, p.Access));
    }

    [Fact]
    public void Address_in_subnet_3_needs_temporary_addresses_for_the_other_three()
    {
        var eth = TestData.Adapter("Ethernet", 1, new[] { "192.168.3.7/24" });
        var plans = ReachabilityPlanner.Plan(eth, new[] { eth });

        Assert.Equal(SubnetAccess.OnLink, For(plans, "192.168.3.0/24").Access);
        Assert.Equal(3, plans.Count(p => p.Access == SubnetAccess.NeedsTemporaryAddress));
    }

    [Fact]
    public void Address_in_one_subnet_only_needs_the_other()
    {
        var eth = TestData.Adapter("Ethernet", 1, new[] { "192.168.1.100/24" });
        var plans = ReachabilityPlanner.Plan(eth, new[] { eth });

        Assert.Equal(SubnetAccess.OnLink, For(plans, "192.168.1.0/24").Access);
        Assert.Equal("192.168.1.100", For(plans, "192.168.1.0/24").ExistingSource!.ToString());
        Assert.Equal(SubnetAccess.NeedsTemporaryAddress, For(plans, "192.168.0.0/24").Access);
    }

    [Fact]
    public void Wide_prefix_covers_both_subnets()
    {
        var eth = TestData.Adapter("Ethernet", 1, new[] { "192.168.5.5/16" });
        var plans = ReachabilityPlanner.Plan(eth, new[] { eth });

        Assert.All(plans, p => Assert.Equal(SubnetAccess.OnLink, p.Access));
    }

    [Fact]
    public void Adapter_without_ipv4_needs_temporary_addresses()
    {
        var eth = TestData.Adapter("Ethernet", 1, Array.Empty<string>());
        var plans = ReachabilityPlanner.Plan(eth, new[] { eth });

        Assert.All(plans, p => Assert.Equal(SubnetAccess.NeedsTemporaryAddress, p.Access));
    }

    [Fact]
    public void Other_adapter_in_target_subnet_still_gets_a_temporary_address_with_a_warning()
    {
        var eth = TestData.Adapter("Ethernet", 1, new[] { "192.168.10.25/24" });
        var wifi = TestData.Adapter("Wi-Fi", 2, new[] { "192.168.1.100/24" });
        var plans = ReachabilityPlanner.Plan(eth, new[] { eth, wifi });

        var shared = For(plans, "192.168.1.0/24");
        Assert.Equal(SubnetAccess.NeedsTemporaryAddress, shared.Access);
        Assert.Equal("Wi-Fi", Assert.Single(shared.ConflictingAdapters));
        Assert.NotEmpty(shared.Warnings);

        var other = For(plans, "192.168.0.0/24");
        Assert.Equal(SubnetAccess.NeedsTemporaryAddress, other.Access);
        Assert.Empty(other.ConflictingAdapters);
    }

    [Fact]
    public void Overlapping_longer_prefix_on_selected_adapter_is_still_blocked()
    {
        var eth = TestData.Adapter("Ethernet", 1, new[] { "192.168.1.5/28" });
        var plan = For(ReachabilityPlanner.Plan(eth, new[] { eth }), "192.168.1.0/24");

        Assert.Equal(SubnetAccess.Blocked, plan.Access);
    }

    [Fact]
    public void Other_adapter_in_same_subnet_only_warns_when_selected_is_already_on_link()
    {
        var eth = TestData.Adapter("Ethernet", 1, new[] { "192.168.1.20/24" });
        var wifi = TestData.Adapter("Wi-Fi", 2, new[] { "192.168.1.100/24" });
        var plan = For(ReachabilityPlanner.Plan(eth, new[] { eth, wifi }), "192.168.1.0/24");

        Assert.Equal(SubnetAccess.OnLink, plan.Access);
        Assert.NotEmpty(plan.Warnings);
    }

    [Fact]
    public void Disconnected_other_adapter_is_ignored()
    {
        var eth = TestData.Adapter("Ethernet", 1, new[] { "192.168.10.25/24" });
        var wifi = TestData.Adapter("Wi-Fi", 2, new[] { "192.168.1.100/24" }, up: false);

        Assert.Equal(SubnetAccess.NeedsTemporaryAddress,
            For(ReachabilityPlanner.Plan(eth, new[] { eth, wifi }), "192.168.1.0/24").Access);
    }
}
