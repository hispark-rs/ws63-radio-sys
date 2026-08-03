#include "hisi_wpa_hostap_compat.h"
#include "l2_packet/l2_packet.h"

#include "hisi_wpa_ap_driver_port.h"

#define HISI_WPA_EAPOL_ETHERTYPE 0x888eu

struct l2_packet_data {
    struct hisi_wpa_ap_driver_hooks hooks;
    uint8_t own_address[ETH_ALEN];
    unsigned short protocol;
    int include_l2_header;
};

struct l2_packet_data *l2_packet_init(const char *ifname,
    const uint8_t *own_address, unsigned short protocol,
    void (*receive)(void *context, const uint8_t *source,
        const uint8_t *frame, size_t frame_len),
    void *receive_context, int include_l2_header)
{
    const struct hisi_wpa_ap_driver_hooks *hooks =
        hisi_wpa_ap_driver_acquire();
    struct l2_packet_data *l2;
    (void) ifname;
    (void) receive;
    (void) receive_context;
    if (hooks == NULL || protocol != HISI_WPA_EAPOL_ETHERTYPE)
        goto failed;
    l2 = os_zalloc(sizeof(*l2));
    if (l2 == NULL)
        goto failed;
    l2->hooks = *hooks;
    if (own_address != NULL) {
        os_memcpy(l2->own_address, own_address, ETH_ALEN);
    } else if (l2->hooks.get_own_address(l2->hooks.driver,
        l2->own_address) != 0) {
        os_free(l2);
        goto failed;
    }
    l2->protocol = protocol;
    l2->include_l2_header = include_l2_header != 0;
    return l2;

failed:
    if (hooks != NULL)
        hisi_wpa_ap_driver_release();
    return NULL;
}

struct l2_packet_data *l2_packet_init_bridge(const char *bridge_ifname,
    const char *ifname, const uint8_t *own_address, unsigned short protocol,
    void (*receive)(void *context, const uint8_t *source,
        const uint8_t *frame, size_t frame_len),
    void *receive_context, int include_l2_header)
{
    (void) bridge_ifname;
    return l2_packet_init(ifname, own_address, protocol, receive,
        receive_context, include_l2_header);
}

void l2_packet_deinit(struct l2_packet_data *l2)
{
    if (l2 == NULL)
        return;
    os_memset(l2, 0, sizeof(*l2));
    os_free(l2);
    hisi_wpa_ap_driver_release();
}

int l2_packet_get_own_addr(struct l2_packet_data *l2, uint8_t *address)
{
    if (l2 == NULL || address == NULL)
        return -1;
    os_memcpy(address, l2->own_address, ETH_ALEN);
    return 0;
}

int l2_packet_send(struct l2_packet_data *l2, const uint8_t *destination,
    uint16_t protocol, const uint8_t *frame, size_t frame_len)
{
    const uint8_t *resolved_destination = destination;
    const uint8_t *payload = frame;
    size_t payload_len = frame_len;
    if (l2 == NULL || frame == NULL || frame_len == 0 ||
        protocol != l2->protocol)
        return -1;
    if (l2->include_l2_header) {
        const struct l2_ethhdr *header;
        if (frame_len < sizeof(*header))
            return -1;
        header = (const struct l2_ethhdr *) frame;
        resolved_destination = header->h_dest;
        payload += sizeof(*header);
        payload_len -= sizeof(*header);
    }
    if (resolved_destination == NULL || payload_len == 0)
        return -1;
    return l2->hooks.send_eapol(l2->hooks.driver, resolved_destination,
        payload, payload_len);
}

int l2_packet_get_ip_addr(struct l2_packet_data *l2, char *buffer, size_t len)
{
    (void) l2;
    (void) buffer;
    (void) len;
    return -1;
}

void l2_packet_notify_auth_start(struct l2_packet_data *l2)
{
    (void) l2;
}

int l2_packet_set_packet_filter(struct l2_packet_data *l2,
    enum l2_packet_filter_type type)
{
    (void) l2;
    (void) type;
    return -1;
}
