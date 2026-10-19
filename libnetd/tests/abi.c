#include <assert.h>
#include <errno.h>
#include <string.h>

#include <peios/netd.h>

#define TEXT(value) ((peios_netd_bytes){(const uint8_t *)(value), sizeof(value) - 1})

static void expect_text(peios_netd_bytes actual, const char *expected) {
    assert(actual.len == strlen(expected));
    assert(memcmp(actual.data, expected, actual.len) == 0);
}

static void hostname_and_errors(void) {
    peios_netd_result *result = peios_netd_hostname_check(TEXT("  workstation  "));
    assert(peios_netd_result_error(result) == 0);
    expect_text(peios_netd_result_text(result), "workstation");
    assert(peios_netd_result_status(result) == NULL);
    peios_netd_result_free(result);

    result = peios_netd_hostname_check(TEXT("not.a.host"));
    assert(peios_netd_result_error(result) == EINVAL);
    assert(peios_netd_result_message(result).len > 0);
    peios_netd_result_free(result);

    result = peios_netd_hostname_check((peios_netd_bytes){NULL, 1});
    assert(peios_netd_result_error(result) == EINVAL);
    peios_netd_result_free(result);
    result = peios_netd_get_status(TEXT(""), 10);
    assert(peios_netd_result_error(result) == EINVAL);
    peios_netd_result_free(result);
    peios_netd_result_free(NULL);
    peios_netd_subscription_free(NULL);
}

static void profiles_and_policy(void) {
    const peios_netd_value values[] = {
        {.name = TEXT("Address.Offered"), .kind = PEIOS_NETD_VALUE_INTEGER, .integer = 1},
        {.name = TEXT("Route.Metric"), .kind = PEIOS_NETD_VALUE_INTEGER, .integer = 77},
        {.name = TEXT("Dns.Servers"), .kind = PEIOS_NETD_VALUE_STRING, .text = TEXT("192.0.2.53")},
    };
    char profile_name[] = "default";
    const peios_netd_key profile = {
        .name = TEXT(profile_name),
        .values = values,
        .value_count = 3,
    };
    const peios_netd_key profiles = {
        .name = TEXT("Profiles"),
        .children = &profile,
        .child_count = 1,
    };
    const peios_netd_bytes actions[] = {TEXT("JOIN(DEFAULT)")};
    const peios_netd_value action = {
        .name = TEXT("Actions"),
        .kind = PEIOS_NETD_VALUE_STRING_LIST,
        .list = {actions, 1},
    };
    const peios_netd_key rule = {
        .name = TEXT("all"),
        .values = &action,
        .value_count = 1,
    };
    const peios_netd_key rules = {
        .name = TEXT("Interface"),
        .children = &rule,
        .child_count = 1,
    };
    peios_netd_result *policy = peios_netd_policy_build(&rules, &profiles);
    assert(peios_netd_result_error(policy) == 0);
    /* Results own their data; modifying the original strings cannot change them. */
    profile_name[0] = 'x';
    assert(peios_netd_policy_profile_count(policy) == 1);
    assert(peios_netd_policy_profile(policy, 1) == NULL);
    const peios_netd_profile *view = peios_netd_policy_profile(policy, 0);
    expect_text(view->path, "default");
    assert(view->enabled == 1 && view->offered == 1);
    assert(view->route_metric.present == 1 && view->route_metric.value == 77);
    assert(view->mtu.present == 0);
    assert(view->dns_servers.len == 1);
    expect_text(view->dns_servers.data[0], "192.0.2.53");

    peios_netd_facts facts = {0};
    peios_netd_result *judgment = peios_netd_policy_judge(policy, &facts);
    assert(peios_netd_result_error(judgment) == 0);
    const peios_netd_judgment *answer = peios_netd_result_judgment(judgment);
    assert(answer && answer->outcome == PEIOS_NETD_OUTCOME_JOIN);
    expect_text(answer->rule, "all");
    expect_text(answer->profile->path, "default");
    peios_netd_result_free(policy);
    /* A judgment also owns its profile independently from the source policy. */
    assert(answer->profile->route_metric.value == 77);
    peios_netd_result_free(judgment);
}

static void invalid_configuration(void) {
    const peios_netd_bytes actions[] = {TEXT("ééé")};
    const peios_netd_value action = {
        .name = TEXT("Actions"),
        .kind = PEIOS_NETD_VALUE_STRING_LIST,
        .list = {actions, 1},
    };
    const peios_netd_key rule = {.name = TEXT("bad"), .values = &action, .value_count = 1};
    peios_netd_key root = {.name = TEXT("Interface"), .children = &rule, .child_count = 1};
    peios_netd_result *result = peios_netd_policy_build(&root, NULL);
    assert(peios_netd_result_error(result) == EINVAL);
    peios_netd_result_free(result);

    /* A caller-owned cyclic graph is readable but must not recurse forever. */
    root.children = &root;
    result = peios_netd_profiles_resolve(&root);
    assert(peios_netd_result_error(result) == EINVAL);
    peios_netd_result_free(result);
}

int main(void) {
    assert(peios_netd_abi_version() == PEIOS_NETD_ABI_VERSION);
    hostname_and_errors();
    profiles_and_policy();
    invalid_configuration();
    return 0;
}
