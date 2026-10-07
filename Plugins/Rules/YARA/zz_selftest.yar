rule ZETA_YaraSmokeTest_9F3A2C
{
    meta:
        description = "ZETA YARA smoke test - matches only a synthetic marker, never real files"
        author      = "zeta-selfcheck"
        date        = "2026-10-06"
    strings:
        $marker = "ZETA_YARA_SMOKE_TEST_MARKER_9F3A2C7E" ascii wide
    condition:
        $marker
}
