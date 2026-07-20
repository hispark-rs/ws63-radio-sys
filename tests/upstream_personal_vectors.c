#include "utils/includes.h"
#include <assert.h>

#include "utils/common.h"
#include "common/eapol_common.h"
#include "common/ieee802_11_defs.h"
#include "common/sae.h"
#include "common/wpa_common.h"
#include "utils/wpabuf.h"

static void expect_bytes(const uint8_t *actual, const uint8_t *expected,
    size_t length)
{
    assert(memcmp(actual, expected, length) == 0);
}

static void test_wpa2_eapol_key_vector(void)
{
    static const uint8_t pmk[PMK_LEN] = {
        [0 ... PMK_LEN - 1] = 0x44,
    };
    static const uint8_t authenticator[ETH_ALEN] = {
        0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
    };
    static const uint8_t supplicant[ETH_ALEN] = {
        0x32, 0x32, 0x32, 0x32, 0x32, 0x32,
    };
    static const uint8_t anonce[WPA_NONCE_LEN] = {
        0x03, 0xf0, 0x23, 0x77, 0xb5, 0xf3, 0xeb, 0xd0,
        0x06, 0x1a, 0x12, 0x9c, 0xd8, 0x23, 0xdf, 0x1e,
        0xaa, 0xf2, 0xe5, 0xe6, 0x94, 0x48, 0xe1, 0xa8,
        0xcb, 0xad, 0x5d, 0x7b, 0x2e, 0x95, 0x6b, 0x01,
    };
    static const uint8_t snonce[WPA_NONCE_LEN] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    static const uint8_t expected_ptk[48] = {
        0x3a, 0x20, 0x25, 0x20, 0x13, 0xa2, 0x49, 0xd8,
        0x00, 0xe3, 0xa2, 0xde, 0x03, 0x8e, 0xcf, 0x84,
        0x55, 0xcf, 0xe0, 0xd3, 0xfd, 0x68, 0x33, 0xdb,
        0x35, 0x72, 0x78, 0x24, 0xcf, 0x65, 0xc5, 0xa1,
        0x4d, 0xfd, 0x5f, 0x9c, 0x2f, 0xd2, 0x9d, 0x7a,
        0x2b, 0x87, 0xa1, 0x18, 0xdb, 0x63, 0x93, 0xf4,
    };
    static const uint8_t expected_mic[16] = {
        0xdb, 0xc6, 0x92, 0x34, 0xbe, 0x4d, 0xa8, 0xbd,
        0xea, 0x11, 0x55, 0x5e, 0xb5, 0xc1, 0x7a, 0xc8,
    };
    static const uint8_t rsne[] = {
        0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,
        0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00,
        0x00, 0x0f, 0xac, 0x02, 0x80, 0x00,
    };
    struct wpa_ptk ptk = { 0 };
    uint8_t eapol_m2[121] = { 0 };
    uint8_t mic[sizeof(expected_mic)] = { 0 };

    assert(wpa_pmk_to_ptk(pmk, sizeof(pmk), "Pairwise key expansion",
        authenticator, supplicant, anonce, snonce, &ptk,
        WPA_KEY_MGMT_PSK, WPA_CIPHER_CCMP, NULL, 0, 0) == 0);
    assert(ptk.kck_len == 16 && ptk.kek_len == 16 && ptk.tk_len == 16);
    expect_bytes(ptk.kck, expected_ptk, 16);
    expect_bytes(ptk.kek, expected_ptk + 16, 16);
    expect_bytes(ptk.tk, expected_ptk + 32, 16);

    eapol_m2[0] = 2;
    eapol_m2[1] = IEEE802_1X_TYPE_EAPOL_KEY;
    WPA_PUT_BE16(&eapol_m2[2], sizeof(eapol_m2) - 4);
    eapol_m2[4] = EAPOL_KEY_TYPE_RSN;
    WPA_PUT_BE16(&eapol_m2[5], WPA_KEY_INFO_KEY_TYPE |
        WPA_KEY_INFO_MIC | WPA_KEY_INFO_TYPE_HMAC_SHA1_AES);
    eapol_m2[16] = 1;
    memcpy(&eapol_m2[17], snonce, sizeof(snonce));
    WPA_PUT_BE16(&eapol_m2[97], sizeof(rsne));
    memcpy(&eapol_m2[99], rsne, sizeof(rsne));
    assert(wpa_eapol_key_mic(ptk.kck, ptk.kck_len, WPA_KEY_MGMT_PSK,
        WPA_KEY_INFO_TYPE_HMAC_SHA1_AES, eapol_m2, sizeof(eapol_m2),
        mic) == 0);
    expect_bytes(mic, expected_mic, sizeof(expected_mic));
}

static void expect_rsne(const uint8_t *rsne, size_t length,
    int expected_key_mgmt, int expected_capabilities)
{
    struct wpa_ie_data parsed;

    assert(wpa_parse_wpa_ie_rsn(rsne, length, &parsed) == 0);
    assert(parsed.proto == WPA_PROTO_RSN);
    assert(parsed.group_cipher == WPA_CIPHER_CCMP);
    assert(parsed.pairwise_cipher == WPA_CIPHER_CCMP);
    assert(parsed.key_mgmt == expected_key_mgmt);
    assert(parsed.capabilities == expected_capabilities);
    assert(parsed.mgmt_group_cipher == WPA_CIPHER_AES_128_CMAC);
}

static void test_rsne_and_pmf_vectors(void)
{
    static const uint8_t wpa2_pmf_optional[] = {
        0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,
        0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00,
        0x00, 0x0f, 0xac, 0x02, 0x80, 0x00,
    };
    static const uint8_t wpa3_sae_required[] = {
        0x30, 0x1a, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,
        0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00,
        0x00, 0x0f, 0xac, 0x08, 0xc0, 0x00, 0x00, 0x00,
        0x00, 0x0f, 0xac, 0x06,
    };
    static const uint8_t transition_pmf_optional[] = {
        0x30, 0x1e, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,
        0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x02, 0x00,
        0x00, 0x0f, 0xac, 0x02, 0x00, 0x0f, 0xac, 0x08,
        0x80, 0x00, 0x00, 0x00, 0x00, 0x0f, 0xac, 0x06,
    };
    static const uint8_t truncated[] = {
        0x30, 0x14, 0x01, 0x00, 0x00, 0x0f,
    };

    expect_rsne(wpa2_pmf_optional, sizeof(wpa2_pmf_optional),
        WPA_KEY_MGMT_PSK, WPA_CAPABILITY_MFPC);
    expect_rsne(wpa3_sae_required, sizeof(wpa3_sae_required),
        WPA_KEY_MGMT_SAE, WPA_CAPABILITY_MFPC | WPA_CAPABILITY_MFPR);
    expect_rsne(transition_pmf_optional, sizeof(transition_pmf_optional),
        WPA_KEY_MGMT_PSK | WPA_KEY_MGMT_SAE, WPA_CAPABILITY_MFPC);
    assert(wpa_parse_wpa_ie_rsn(truncated, sizeof(truncated),
        &(struct wpa_ie_data) { 0 }) < 0);
}

static void run_sae_roundtrip(bool hash_to_element)
{
    static const uint8_t address_a[ETH_ALEN] = {
        0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
    };
    static const uint8_t address_b[ETH_ALEN] = {
        0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
    };
    static const uint8_t ssid[] = "hisi-sae-vector";
    static const uint8_t password[] = "correct horse battery staple";
    struct sae_data a = { .akmp = WPA_KEY_MGMT_SAE };
    struct sae_data b = { .akmp = WPA_KEY_MGMT_SAE };
    struct sae_pt *pt = NULL;
    struct wpabuf *commit_a = NULL;
    struct wpabuf *commit_b = NULL;
    struct wpabuf *confirm_a = NULL;
    struct wpabuf *confirm_b = NULL;
    struct wpabuf *anti_clogging = NULL;
    const uint8_t *token = NULL;
    size_t token_len = 0;
    int groups[] = { 19, 0 };

    assert(sae_set_group(&a, 19) == 0);
    assert(sae_set_group(&b, 19) == 0);
    if (hash_to_element) {
        pt = sae_derive_pt(groups, ssid, sizeof(ssid) - 1,
            password, sizeof(password) - 1, NULL);
        assert(pt != NULL);
        assert(sae_prepare_commit_pt(&a, pt, address_a, address_b,
            NULL, NULL) == 0);
        assert(sae_prepare_commit_pt(&b, pt, address_b, address_a,
            NULL, NULL) == 0);
    } else {
        assert(sae_prepare_commit(address_a, address_b, password,
            sizeof(password) - 1, &a) == 0);
        assert(sae_prepare_commit(address_b, address_a, password,
            sizeof(password) - 1, &b) == 0);
    }

    commit_a = wpabuf_alloc(SAE_COMMIT_MAX_LEN);
    commit_b = wpabuf_alloc(SAE_COMMIT_MAX_LEN);
    confirm_a = wpabuf_alloc(SAE_CONFIRM_MAX_LEN);
    confirm_b = wpabuf_alloc(SAE_CONFIRM_MAX_LEN);
    assert(commit_a != NULL && commit_b != NULL);
    assert(confirm_a != NULL && confirm_b != NULL);
    if (hash_to_element) {
        static const uint8_t anti_clogging_value[] = {
            0x11, 0x22, 0x33, 0x44,
        };

        anti_clogging = wpabuf_alloc_copy(anti_clogging_value,
            sizeof(anti_clogging_value));
        assert(anti_clogging != NULL);
    }
    assert(sae_write_commit(&a, commit_a, anti_clogging, NULL) == 0);
    assert(sae_write_commit(&b, commit_b, NULL, NULL) == 0);
    assert(sae_parse_commit(&a, wpabuf_head(commit_b),
        wpabuf_len(commit_b), &token, &token_len, groups,
        hash_to_element, NULL) == WLAN_STATUS_SUCCESS);
    if (hash_to_element) {
        /* Regression for hostap advisory 2026-3: SME/PASN callers do not
         * request the parsed token, so a valid H2E token container must not
         * dereference NULL token output pointers. */
        assert(sae_parse_commit(&b, wpabuf_head(commit_a),
            wpabuf_len(commit_a), NULL, NULL, groups, 1, NULL) ==
            WLAN_STATUS_SUCCESS);
    } else {
        assert(sae_parse_commit(&b, wpabuf_head(commit_a),
            wpabuf_len(commit_a), &token, &token_len, groups, 0, NULL) ==
            WLAN_STATUS_SUCCESS);
    }
    assert(sae_process_commit(&a) == 0);
    assert(sae_process_commit(&b) == 0);
    assert(a.pmk_len == SAE_PMK_LEN && b.pmk_len == SAE_PMK_LEN);
    expect_bytes(a.pmk, b.pmk, SAE_PMK_LEN);
    expect_bytes(a.pmkid, b.pmkid, SAE_PMKID_LEN);

    assert(sae_write_confirm(&a, confirm_a) == 0);
    assert(sae_write_confirm(&b, confirm_b) == 0);
    assert(sae_check_confirm(&a, wpabuf_head(confirm_b),
        wpabuf_len(confirm_b), NULL) == 0);
    assert(sae_check_confirm(&b, wpabuf_head(confirm_a),
        wpabuf_len(confirm_a), NULL) == 0);

    wpabuf_free(confirm_b);
    wpabuf_free(confirm_a);
    wpabuf_free(commit_b);
    wpabuf_free(commit_a);
    wpabuf_free(anti_clogging);
    sae_deinit_pt(pt);
    sae_clear_data(&b);
    sae_clear_data(&a);
}

int main(void)
{
    assert(os_program_init() == 0);
    wpa_debug_level = MSG_ERROR + 1;
    test_wpa2_eapol_key_vector();
    test_rsne_and_pmf_vectors();
    run_sae_roundtrip(false);
    run_sae_roundtrip(true);
    os_program_deinit();
    return 0;
}
