#include "dhcpd.h"

PUBLIC char *dhcpv4_msg_to_string(u8 reqmsg)
{
    switch (reqmsg) {
    case (DHCPV4_MSG_DISCOVER): return "DHCPV4_MSG_DISCOVER";
    case (DHCPV4_MSG_OFFER): return "DHCPV4_MSG_OFFER";
    case (DHCPV4_MSG_REQUEST): return "DHCPV4_MSG_REQUEST";
    case (DHCPV4_MSG_DECLINE): return "DHCPV4_MSG_DECLINE";
    case (DHCPV4_MSG_ACK): return "DHCPV4_MSG_ACK";
    case (DHCPV4_MSG_NAK): return "DHCPV4_MSG_NAK";
    case (DHCPV4_MSG_RELEASE): return "DHCPV4_MSG_RELEASE";
    case (DHCPV4_MSG_INFORM): return "DHCPV4_MSG_INFORM";
    case (DHCPV4_MSG_FORCERENEW): return "DHCPV4_MSG_FORCERENEW";
    default: return "UNKNOWN";
    }
}

PUBLIC void dhcpv4_put(struct dhcpv4_message *msg, u8 **cookie, u8 type, u8 len, const void *data)
{
    u8 *c = *cookie;
    u8 *end = (u8 *)msg + sizeof(*msg);
    bool tag_only = type == DHCPV4_OPT_PAD || type == DHCPV4_OPT_END;
    int total_len = tag_only ? 1 : 2 + len;

    if (*cookie + total_len > end)
        return;

    *cookie += total_len;
    *c++ = type;

    if (tag_only)
        return;

    *c++ = len;
    memcpy(c, data, len);
}
