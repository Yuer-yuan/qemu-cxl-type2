#include "qemu/osdep.h"

#include "hw/cxl/cxl_type3_memsim_v2.h"
#include "qapi/error.h"

static void test_default_config_is_disabled_and_valid(void)
{
    CxlType3MemsimV2Config config = cxl_type3_memsim_v2_default_config();
    Error *err = NULL;

    g_assert_false(config.enabled);
    g_assert_false(config.read_exclusive);
    g_assert_true(cxl_type3_memsim_v2_validate(&config, &err));
    g_assert_null(err);
}

static void test_enabled_config_rejects_invalid_host_id(void)
{
    CxlType3MemsimV2Config config = cxl_type3_memsim_v2_default_config();
    Error *err = NULL;

    config.enabled = true;
    config.host_id = CXL_MEMSIM_V2_MAX_ENDPOINTS;
    g_assert_false(cxl_type3_memsim_v2_validate(&config, &err));
    g_assert_nonnull(err);
    error_free(err);
}

static void test_enabled_config_rejects_invalid_geometry(void)
{
    CxlType3MemsimV2Config config = cxl_type3_memsim_v2_default_config();
    Error *err = NULL;

    config.enabled = true;
    config.cache_capacity = CXL_MEMSIM_V2_LINE_SIZE + 1;
    g_assert_false(cxl_type3_memsim_v2_validate(&config, &err));
    g_assert_nonnull(err);
    error_free(err);
}

static void test_enabled_config_rejects_write_through(void)
{
    CxlType3MemsimV2Config config = cxl_type3_memsim_v2_default_config();
    Error *err = NULL;

    config.enabled = true;
    config.write_through = true;
    g_assert_false(cxl_type3_memsim_v2_validate(&config, &err));
    g_assert_nonnull(err);
    error_free(err);
}

static void test_enabled_access_without_session_fails_closed(void)
{
    CxlType3MemsimV2 state = {
        .config = cxl_type3_memsim_v2_default_config(),
        .enabled = true,
    };
    uint64_t value = 0;

    g_assert_cmpint(cxl_type3_memsim_v2_read(&state, 0, &value, 8),
                    ==, MEMTX_ERROR);
    g_assert_cmpint(cxl_type3_memsim_v2_write(&state, 0, 1, 8),
                    ==, MEMTX_ERROR);
}

static void test_gpf_configuration(void)
{
    CxlType3MemsimV2Config config = cxl_type3_memsim_v2_default_config();
    Error *err = NULL;

    g_assert_false(config.gpf);
    config.gpf = true;
    g_assert_false(cxl_type3_memsim_v2_validate(&config, &err));
    g_assert_nonnull(err);
    g_clear_pointer(&err, error_free);
    config.enabled = true;
    config.gpf_state_file = "unused-state-file";
    g_assert_true(cxl_type3_memsim_v2_validate(&config, &err));
    g_assert_null(err);
    g_assert_cmphex(cxl_type3_memsim_v2_gpf_duration(&config), ==, 0x060a);
    config.timeout_ms = 75000;
    g_assert_true(cxl_type3_memsim_v2_validate(&config, &err));
    g_assert_cmphex(cxl_type3_memsim_v2_gpf_duration(&config), ==, 0x070f);
    config.timeout_ms++;
    g_assert_false(cxl_type3_memsim_v2_validate(&config, &err));
    g_assert_nonnull(err);
    error_free(err);
}

static void test_gpf_shutdown_state_survives_restart(void)
{
    g_autofree char *directory = g_dir_make_tmp("qemu-gpf-state-XXXXXX",
                                                NULL);
    g_autofree char *path = g_build_filename(directory, "endpoint.state",
                                             NULL);
    CxlType3MemsimV2 first = {
        .config = cxl_type3_memsim_v2_default_config(),
    };
    CxlType3MemsimV2 second = {
        .config = cxl_type3_memsim_v2_default_config(),
    };
    CxlType3MemsimV2 clean_restart = {
        .config = cxl_type3_memsim_v2_default_config(),
    };
    Error *err = NULL;

    first.config.gpf = true;
    first.config.gpf_state_file = path;
    g_assert_true(cxl_type3_memsim_v2_init_shutdown_state(&first, &err));
    g_assert_null(err);
    g_assert_cmpuint(cxl_type3_memsim_v2_get_shutdown_state(&first), ==, 0);
    g_assert_cmpuint(cxl_type3_memsim_v2_dirty_shutdown_count(&first), ==, 0);
    g_assert_true(cxl_type3_memsim_v2_set_shutdown_state(&first, 1, &err));

    second.config.gpf = true;
    second.config.gpf_state_file = path;
    g_assert_true(cxl_type3_memsim_v2_init_shutdown_state(&second, &err));
    g_assert_null(err);
    g_assert_cmpuint(cxl_type3_memsim_v2_get_shutdown_state(&second), ==, 1);
    g_assert_cmpuint(cxl_type3_memsim_v2_dirty_shutdown_count(&second), ==, 1);
    g_assert_true(cxl_type3_memsim_v2_set_shutdown_state(&second, 0, &err));

    clean_restart.config.gpf = true;
    clean_restart.config.gpf_state_file = path;
    g_assert_true(cxl_type3_memsim_v2_init_shutdown_state(&clean_restart,
                                                          &err));
    g_assert_null(err);
    g_assert_cmpuint(cxl_type3_memsim_v2_get_shutdown_state(&clean_restart),
                     ==, 0);
    g_assert_cmpuint(
        cxl_type3_memsim_v2_dirty_shutdown_count(&clean_restart), ==, 1);
    g_assert_cmpint(g_remove(path), ==, 0);
    g_assert_cmpint(g_rmdir(directory), ==, 0);
}

static void test_gpf_shutdown_state_rejects_corruption(void)
{
    g_autofree char *directory = g_dir_make_tmp("qemu-gpf-state-XXXXXX",
                                                NULL);
    g_autofree char *path = g_build_filename(directory, "endpoint.state",
                                             NULL);
    CxlType3MemsimV2 state = {
        .config = cxl_type3_memsim_v2_default_config(),
    };
    Error *err = NULL;

    g_assert_true(g_file_set_contents(path, "corrupt", -1, NULL));
    state.config.gpf = true;
    state.config.gpf_state_file = path;
    g_assert_false(cxl_type3_memsim_v2_init_shutdown_state(&state, &err));
    g_assert_nonnull(err);
    g_assert_nonnull(strstr(error_get_pretty(err), "invalid length"));
    error_free(err);
    g_assert_cmpint(g_remove(path), ==, 0);
    g_assert_cmpint(g_rmdir(directory), ==, 0);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/cxl/type3/memsim-v2/gpf-config", test_gpf_configuration);
    g_test_add_func("/cxl/type3/memsim-v2/gpf-shutdown-state-restart",
                    test_gpf_shutdown_state_survives_restart);
    g_test_add_func("/cxl/type3/memsim-v2/gpf-shutdown-state-corrupt",
                    test_gpf_shutdown_state_rejects_corruption);
    g_test_add_func("/cxl/type3/memsim-v2/default-config",
                    test_default_config_is_disabled_and_valid);
    g_test_add_func("/cxl/type3/memsim-v2/invalid-host-id",
                    test_enabled_config_rejects_invalid_host_id);
    g_test_add_func("/cxl/type3/memsim-v2/invalid-geometry",
                    test_enabled_config_rejects_invalid_geometry);
    g_test_add_func("/cxl/type3/memsim-v2/write-through-rejected",
                    test_enabled_config_rejects_write_through);
    g_test_add_func("/cxl/type3/memsim-v2/fail-closed",
                    test_enabled_access_without_session_fails_closed);
    return g_test_run();
}
