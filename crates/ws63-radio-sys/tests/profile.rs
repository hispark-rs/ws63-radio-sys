use ws63_radio_sys::{ROM_CALLBACK_ROOT_SYMBOLS, WIFI_ARCHIVES, WIFI_ROOT_SYMBOLS};

#[test]
fn archive_profile_is_unique() {
    for (index, archive) in WIFI_ARCHIVES.iter().enumerate() {
        assert!(
            WIFI_ARCHIVES[..index]
                .iter()
                .all(|other| other.name != archive.name)
        );
    }
    assert_eq!(
        WIFI_ARCHIVES
            .iter()
            .filter(|archive| archive.whole_archive)
            .count(),
        1
    );
    assert!(WIFI_ROOT_SYMBOLS.contains(&"dmac_psm_process_tim_elm_patch"));
    assert_eq!(ROM_CALLBACK_ROOT_SYMBOLS.len(), 2);
}
