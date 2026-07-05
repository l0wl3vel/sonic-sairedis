#include "SwitchVpp.h"

#include "meta/sai_serialize.h"

#include "swss/logger.h"

#include <cstring>
#include <cstdio>

#include "vppxlate/SaiVppXlate.h"

using namespace saivs;

/*
 * IPv6 link-local multicast hostif traps for the VPP dataplane.
 *
 * orchagent creates SAI hostif traps (SAI_OBJECT_TYPE_HOSTIF_TRAP) for IPv6 ND
 * and MLD just like it does on a real ASIC. On a real ASIC the trap installs a
 * copy-to-CPU rule so the protocol packets reach the kernel (and therefore FRR).
 *
 * On VPP, link-local multicast (*,G) entries (ff02::/16) are auto-created with an
 * Accept path on each ip6-enabled wire interface plus a local dpo-receive, but VPP
 * never forwards those packets to the linux-cp host tap. The lcp host tap *is* the
 * SAI hostif here, so the layer-correct equivalent of the ASIC trap rule is an mfib
 * FORWARD path to that tap. This file installs those FORWARD paths for the ND/MLD
 * trap types, for every router interface, and keeps them in sync as traps and
 * router interfaces come and go (in either order).
 */

bool SwitchVpp::vpp_get_mcast_punt_prefixes(
        _In_ int32_t trap_type,
        _Out_ std::vector<std::pair<std::array<uint8_t, 16>, uint8_t>> &prefixes)
{
    SWSS_LOG_ENTER();

    prefixes.clear();

    // Build an ff02::/16 link-local group address with the given low-order bytes set.
    auto ff02 = [](std::initializer_list<std::pair<int, uint8_t>> bytes) {
        std::array<uint8_t, 16> a{};   // zero-initialized => (*,G) src is wildcard
        a[0] = 0xff;
        a[1] = 0x02;
        for (const auto &b : bytes)
        {
            a[b.first] = b.second;
        }
        return a;
    };

    switch (trap_type)
    {
        case SAI_HOSTIF_TRAP_TYPE_IPV6_NEIGHBOR_DISCOVERY:
            // RA  -> all-nodes        ff02::1/128
            // RS  -> all-routers      ff02::2/128
            // NS  -> solicited-node   ff02::1:ff00:0/104
            prefixes.push_back({ff02({{15, 0x01}}), 128});
            prefixes.push_back({ff02({{15, 0x02}}), 128});
            prefixes.push_back({ff02({{11, 0x01}, {12, 0xff}}), 104});
            return true;

        case SAI_HOSTIF_TRAP_TYPE_IPV6_MLD_V1_V2:
            // MLD queries/reports     ff02::16/128
            prefixes.push_back({ff02({{15, 0x16}}), 128});
            return true;

        default:
            return false;
    }
}

bool SwitchVpp::vpp_get_rif_lcp_host(
        _In_ sai_object_id_t rif_oid,
        _Out_ uint32_t &host_sw_if_index,
        _Out_ uint32_t &table_id)
{
    SWSS_LOG_ENTER();

    sai_attribute_t attr;

    attr.id = SAI_ROUTER_INTERFACE_ATTR_TYPE;
    if (get(SAI_OBJECT_TYPE_ROUTER_INTERFACE, rif_oid, 1, &attr) != SAI_STATUS_SUCCESS)
    {
        return false;
    }
    int32_t rif_type = attr.value.s32;

    // Only port-backed router interfaces have a wire-side lcp tap that receives ND/MLD.
    // Loopback and vlan(BVI) router interfaces do not.
    if (rif_type != SAI_ROUTER_INTERFACE_TYPE_PORT &&
        rif_type != SAI_ROUTER_INTERFACE_TYPE_SUB_PORT)
    {
        return false;
    }

    attr.id = SAI_ROUTER_INTERFACE_ATTR_PORT_ID;
    if (get(SAI_OBJECT_TYPE_ROUTER_INTERFACE, rif_oid, 1, &attr) != SAI_STATUS_SUCCESS)
    {
        return false;
    }
    sai_object_id_t port_oid = attr.value.oid;

    sai_object_type_t ot = objectTypeQuery(port_oid);
    if (ot != SAI_OBJECT_TYPE_PORT)
    {
        // LAG / VLAN router interfaces are out of scope (mini-lab fabric uses ports).
        SWSS_LOG_INFO("skip ipv6 mcast punt for rif %s: port id is %s",
                sai_serialize_object_id(rif_oid).c_str(),
                sai_serialize_object_type(ot).c_str());
        return false;
    }

    std::string if_name;
    if (getTapNameFromPortId(port_oid, if_name) == false)
    {
        SWSS_LOG_INFO("skip ipv6 mcast punt for rif %s: no tap for port %s",
                sai_serialize_object_id(rif_oid).c_str(),
                sai_serialize_object_id(port_oid).c_str());
        return false;
    }

    uint16_t vlan_id = 0;
    if (rif_type == SAI_ROUTER_INTERFACE_TYPE_SUB_PORT)
    {
        attr.id = SAI_ROUTER_INTERFACE_ATTR_OUTER_VLAN_ID;
        if (get(SAI_OBJECT_TYPE_ROUTER_INTERFACE, rif_oid, 1, &attr) == SAI_STATUS_SUCCESS)
        {
            vlan_id = attr.value.u16;
        }
    }

    const char *hwif = tap_to_hwif_name(if_name.c_str());
    if (hwif == nullptr || strcmp(hwif, "Unknown") == 0)
    {
        SWSS_LOG_INFO("skip ipv6 mcast punt for rif %s: no hwif for tap %s",
                sai_serialize_object_id(rif_oid).c_str(), if_name.c_str());
        return false;
    }

    char hwif_buf[64];
    char linux_buf[64];
    const char *hwif_name;
    const char *linux_ifname;

    if (vlan_id)
    {
        snprintf(hwif_buf, sizeof(hwif_buf), "%s.%u", hwif, vlan_id);
        snprintf(linux_buf, sizeof(linux_buf), "%s.%u", if_name.c_str(), vlan_id);
        hwif_name = hwif_buf;
        linux_ifname = linux_buf;
    }
    else
    {
        hwif_name = hwif;
        linux_ifname = if_name.c_str();
    }

    uint32_t host = (uint32_t) ~0;
    if (lcp_itf_pair_get_host_sw_if_index(hwif_name, &host) != 0)
    {
        // lcp pair not up yet; caller will retry on the next trap/rif event.
        return false;
    }

    uint32_t vrf_id = 0;
    if (vpp_get_vrf_id(linux_ifname, &vrf_id) != 0)
    {
        vrf_id = 0;
    }

    host_sw_if_index = host;
    table_id = vrf_id;

    return true;
}

sai_status_t SwitchVpp::vpp_mcast_punt_install(
        _In_ uint32_t host_sw_if_index,
        _In_ uint32_t table_id,
        _In_ int32_t trap_type,
        _In_ bool is_add)
{
    SWSS_LOG_ENTER();

    /*
     * Superseded (Option A of sonic-vpp-mcast-inject-implementation-handoff.md):
     * link-local ND/MLD punt to the lcp host tap, and the tap->wire inject
     * these traps were never able to provide, are now handled entirely in
     * the VPP dataplane by the sonic_ext plugin's per-lcp-pair
     * sonic-ext-mcast6-{phy,host} feature (see mcast6_node.c), wired up
     * automatically the moment a linux-cp pair is created -- no hostif
     * trap or per-VRF mfib entry required.
     *
     * A global (*,G) mfib Forward path programmed here would now just be
     * a second, redundant delivery path (duplicate RAs reaching FRR) with
     * the cross-leak exposure this handoff explicitly moved away from
     * (a single table_id entry floods to every port sharing that VRF).
     * Left as a no-op rather than deleted so the hostif-trap/RIF
     * bookkeeping above (m_mcast_punt_trap_types, vpp_get_rif_lcp_host)
     * keeps working unchanged if this ever needs to be revisited.
     */
    (void) host_sw_if_index;
    (void) table_id;
    (void) trap_type;
    (void) is_add;

    return SAI_STATUS_SUCCESS;
}

sai_status_t SwitchVpp::vpp_mcast_punt_program_trap(
        _In_ int32_t trap_type,
        _In_ bool is_add)
{
    SWSS_LOG_ENTER();

    auto it = m_objectHash.find(SAI_OBJECT_TYPE_ROUTER_INTERFACE);
    if (it == m_objectHash.end())
    {
        return SAI_STATUS_SUCCESS;
    }

    for (const auto &kv : it->second)
    {
        sai_object_id_t rif_oid;
        sai_deserialize_object_id(kv.first, rif_oid);

        uint32_t host_sw_if_index = (uint32_t) ~0;
        uint32_t table_id = 0;
        if (vpp_get_rif_lcp_host(rif_oid, host_sw_if_index, table_id))
        {
            vpp_mcast_punt_install(host_sw_if_index, table_id, trap_type, is_add);
        }
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t SwitchVpp::vpp_mcast_punt_program_rif(
        _In_ sai_object_id_t rif_oid,
        _In_ bool is_add)
{
    SWSS_LOG_ENTER();

    if (m_mcast_punt_trap_types.empty())
    {
        return SAI_STATUS_SUCCESS;
    }

    uint32_t host_sw_if_index = (uint32_t) ~0;
    uint32_t table_id = 0;
    if (vpp_get_rif_lcp_host(rif_oid, host_sw_if_index, table_id) == false)
    {
        return SAI_STATUS_SUCCESS;
    }

    for (int32_t trap_type : m_mcast_punt_trap_types)
    {
        vpp_mcast_punt_install(host_sw_if_index, table_id, trap_type, is_add);
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t SwitchVpp::createHostifTrap(
        _In_ sai_object_id_t object_id,
        _In_ sai_object_id_t switch_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list)
{
    SWSS_LOG_ENTER();

    auto sid = sai_serialize_object_id(object_id);
    CHECK_STATUS(create_internal(SAI_OBJECT_TYPE_HOSTIF_TRAP, sid, switch_id, attr_count, attr_list));

    auto attr_type = sai_metadata_get_attr_by_id(SAI_HOSTIF_TRAP_ATTR_TRAP_TYPE, attr_count, attr_list);
    if (attr_type == nullptr)
    {
        return SAI_STATUS_SUCCESS;
    }
    int32_t trap_type = attr_type->value.s32;

    std::vector<std::pair<std::array<uint8_t, 16>, uint8_t>> prefixes;
    if (vpp_get_mcast_punt_prefixes(trap_type, prefixes) == false)
    {
        // Not an IPv6 link-local multicast trap we need to punt to the host tap.
        return SAI_STATUS_SUCCESS;
    }

    if (m_mcast_punt_trap_types.insert(trap_type).second == false)
    {
        // Already installed.
        return SAI_STATUS_SUCCESS;
    }

    SWSS_LOG_NOTICE("installing ipv6 mcast hostif trap type 0x%x on all router interfaces", trap_type);

    if (m_switchConfig->m_useTapDevice == true)
    {
        vpp_mcast_punt_program_trap(trap_type, true);
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t SwitchVpp::removeHostifTrap(
        _In_ sai_object_id_t object_id)
{
    SWSS_LOG_ENTER();

    sai_attribute_t attr;
    attr.id = SAI_HOSTIF_TRAP_ATTR_TRAP_TYPE;
    int32_t trap_type = -1;
    if (get(SAI_OBJECT_TYPE_HOSTIF_TRAP, object_id, 1, &attr) == SAI_STATUS_SUCCESS)
    {
        trap_type = attr.value.s32;
    }

    if (trap_type != -1 && m_mcast_punt_trap_types.erase(trap_type) > 0)
    {
        SWSS_LOG_NOTICE("removing ipv6 mcast hostif trap type 0x%x from all router interfaces", trap_type);

        if (m_switchConfig->m_useTapDevice == true)
        {
            vpp_mcast_punt_program_trap(trap_type, false);
        }
    }

    auto sid = sai_serialize_object_id(object_id);
    CHECK_STATUS(remove_internal(SAI_OBJECT_TYPE_HOSTIF_TRAP, sid));

    return SAI_STATUS_SUCCESS;
}
