import requests, logging
import pytest, json

from settings import TEST_DATA, DEPLOYMENTS
from suite.custom_resources_utils import (
    create_ap_logconf_from_yaml,
    create_ap_policy_from_yaml,
    delete_ap_policy,
    delete_ap_logconf,
)
from suite.resources_utils import (
    wait_before_test,
    create_example_app,
    wait_until_all_pods_are_ready,
    create_items_from_yaml,
    delete_items_from_yaml,
    delete_common_app,
    ensure_connection_to_public_endpoint,
    ensure_response_from_backend,
    wait_before_test,
    get_events,
    get_ingress_nginx_template_conf,
    get_first_pod_name,
    get_file_contents,
)
from suite.custom_resources_utils import (
    read_ap_crd,
    create_crd_from_yaml,
    delete_crd,
    create_ap_usersig_from_yaml,
    delete_ap_usersig,
    delete_and_create_ap_policy_from_yaml,
    delete_virtual_server,
    create_virtual_server_from_yaml,
    patch_virtual_server_from_yaml,
    create_policy_from_yaml,
    delete_policy,
    read_policy,
)
from suite.yaml_utils import get_first_ingress_host_from_yaml, get_name_from_yaml

std_vs_src = f"{TEST_DATA}/ap-waf/standard/virtual-server.yaml"
waf_vs_src = f"{TEST_DATA}/ap-waf/virtual-server.yaml"
ap_policy_uds = "dataguard-alarm-uds"
uds_crd = f"{DEPLOYMENTS}/common/crds-v1beta1/appprotect.f5.com_apusersigs.yaml"
uds_crd_resource = f"{TEST_DATA}/ap-waf/ap-ic-uds.yaml"
valid_resp_addr = "Server address:"
valid_resp_name = "Server name:"
invalid_resp_title = "Request Rejected"
invalid_resp_body = "The requested URL was rejected. Please consult with your administrator."

@pytest.fixture(scope="class")
def appprotect_setup(request, kube_apis, test_namespace) -> None:
    """
    Deploy simple application and all the AppProtect(dataguard-alarm) resources under test in one namespace.

    :param request: pytest fixture
    :param kube_apis: client apis
    :param ingress_controller_endpoint: public endpoint
    :param test_namespace:
    """

    print("------------------------- Deploy logconf -----------------------------")
    src_log_yaml = f"{TEST_DATA}/ap-waf/logconf.yaml"
    log_name = create_ap_logconf_from_yaml(kube_apis.custom_objects, src_log_yaml, test_namespace)

    print("------------------------- Create UserSig CRD -----------------------------")
    ap_uds_crd_name = get_name_from_yaml(uds_crd)
    create_crd_from_yaml(
        kube_apis.api_extensions_v1_beta1, ap_uds_crd_name, uds_crd,
    )
    wait_before_test()

    print("------------------------- Create UserSig CRD resource-----------------------------")
    usersig_name = create_ap_usersig_from_yaml(
        kube_apis.custom_objects, uds_crd_resource, test_namespace
    )

    print(f"------------------------- Deploy dataguard-alarm appolicy ---------------------------")
    src_pol_yaml = f"{TEST_DATA}/ap-waf/{ap_policy_uds}.yaml"
    pol_name = create_ap_policy_from_yaml(kube_apis.custom_objects, src_pol_yaml, test_namespace)

    def fin():
        print("Clean up:")
        delete_ap_policy(kube_apis.custom_objects, pol_name, test_namespace)  
        delete_ap_usersig(kube_apis.custom_objects, usersig_name, test_namespace)
        delete_crd(
            kube_apis.api_extensions_v1_beta1, ap_uds_crd_name,
        )
        delete_ap_logconf(kube_apis.custom_objects, log_name, test_namespace)

    request.addfinalizer(fin)


def assert_ap_crd_info(ap_crd_info, policy_name) -> None:
    """
    Assert fields in AppProtect policy documents
    :param ap_crd_info: CRD output from k8s API
    """
    assert ap_crd_info["kind"] == "APPolicy"
    assert ap_crd_info["metadata"]["name"] == policy_name
    assert ap_crd_info["spec"]["policy"]["enforcementMode"] == "blocking"
    assert (
        ap_crd_info["spec"]["policy"]["blocking-settings"]["violations"][0]["name"]
        == "VIOL_DATA_GUARD"
    )


def assert_invalid_responses(response) -> None:
    """
    Assert responses when policy config is blocking requests
    :param response: Response
    """
    assert invalid_resp_title in response.text
    assert invalid_resp_body in response.text
    assert response.status_code == 200


def assert_valid_responses(response) -> None:
    """
    Assert responses when policy config is allowing requests
    :param response: Response
    """
    assert valid_resp_name in response.text
    assert valid_resp_addr in response.text
    assert response.status_code == 200


@pytest.mark.skip_for_nginx_oss
@pytest.mark.test
@pytest.mark.parametrize(
    "crd_ingress_controller_with_ap, virtual_server_setup",
    [
        (
            {
                "type": "complete",
                "extra_args": [
                    f"-enable-custom-resources",
                    f"-enable-leader-election=false",
                    f"-enable-app-protect",
                    f"-enable-preview-policies",
                ],
            },
            {"example": "ap-waf", "app_type": "simple",},
        )
    ],
    indirect=True,
)
class TestAppProtect:
    def restore_default_vs(self, kube_apis, virtual_server_setup) -> None:
        """
        Restore VirtualServer without policy spec
        """
        delete_virtual_server(
            kube_apis.custom_objects, virtual_server_setup.vs_name, virtual_server_setup.namespace
        )
        create_virtual_server_from_yaml(
            kube_apis.custom_objects, std_vs_src, virtual_server_setup.namespace
        )
        wait_before_test()

    @pytest.mark.smoke
    @pytest.mark.parametrize("src", [waf_vs_src])
    def test_ap_enable_true_policy_correct(
        self,
        kube_apis,
        crd_ingress_controller_with_ap,
        virtual_server_setup,
        appprotect_setup,
        test_namespace,
        src,
    ):
        """
        Test malicious script request is rejected while AppProtect is enabled in Ingress
        """
        waf_pol_src = f"{TEST_DATA}/ap-waf/waf.yaml"
        print(f"Create waf policy")
        pol_name = create_policy_from_yaml(kube_apis.custom_objects, waf_pol_src, test_namespace)
        wait_before_test()
        # print("--------- Run test while AppProtect module is enabled with correct policy ---------")
        print(f"Patch vs with policy: {src}")
        patch_virtual_server_from_yaml(
            kube_apis.custom_objects,
            virtual_server_setup.vs_name,
            src,
            virtual_server_setup.namespace,
        )
        wait_before_test()
        ap_crd_info = read_ap_crd(
            kube_apis.custom_objects, test_namespace, "appolicies", ap_policy_uds
        )
        assert_ap_crd_info(ap_crd_info, ap_policy_uds)
        wait_before_test(120)

        print("----------------------- Send request ----------------------")
        response = requests.get(
            virtual_server_setup.backend_1_url+"</script>", headers={"host": virtual_server_setup.vs_host},
        )
        print(response.text)
        delete_policy(kube_apis.custom_objects, pol_name, test_namespace)
        self.restore_default_vs(kube_apis, virtual_server_setup)
        assert_invalid_responses(response)

    # def test_ap_enable_false_policy_correct(
    #     self, kube_apis, crd_ingress_controller_with_ap, appprotect_setup, test_namespace
    # ):
    #     """
    #     Test malicious script request is working normally while AppProtect is disabled in Ingress
    #     """
    #     create_ingress_with_ap_annotations(
    #         kube_apis, src_ing_yaml, test_namespace, ap_policy, "False", "True", "127.0.0.1:514"
    #     )
    #     ingress_host = get_first_ingress_host_from_yaml(src_ing_yaml)

    #     print(
    #         "--------- Run test while AppProtect module is disabled with correct policy ---------"
    #     )

    #     ap_crd_info = read_ap_crd(kube_apis.custom_objects, test_namespace, "appolicies", ap_policy)
    #     assert_ap_crd_info(ap_crd_info, ap_policy)
    #     wait_before_test(40)
    #     ensure_response_from_backend(appprotect_setup.req_url, ingress_host)

    #     print("----------------------- Send request ----------------------")
    #     response = requests.get(
    #         appprotect_setup.req_url + "/<script>", headers={"host": ingress_host}, verify=False
    #     )
    #     print(response.text)
    #     delete_items_from_yaml(kube_apis, src_ing_yaml, test_namespace)
    #     assert_valid_responses(response)

    # def test_ap_enable_true_policy_incorrect(
    #     self, kube_apis, crd_ingress_controller_with_ap, appprotect_setup, test_namespace
    # ):
    #     """
    #     Test malicious script request is blocked by default policy while AppProtect is enabled with incorrect policy in ingress
    #     """
    #     create_ingress_with_ap_annotations(
    #         kube_apis,
    #         src_ing_yaml,
    #         test_namespace,
    #         "invalid-policy",
    #         "True",
    #         "True",
    #         "127.0.0.1:514",
    #     )
    #     ingress_host = get_first_ingress_host_from_yaml(src_ing_yaml)

    #     print(
    #         "--------- Run test while AppProtect module is enabled with incorrect policy ---------"
    #     )

    #     wait_before_test(40)
    #     ensure_response_from_backend(appprotect_setup.req_url, ingress_host)

    #     print("----------------------- Send request ----------------------")
    #     response = requests.get(
    #         appprotect_setup.req_url + "/<script>", headers={"host": ingress_host}, verify=False
    #     )
    #     print(response.text)
    #     delete_items_from_yaml(kube_apis, src_ing_yaml, test_namespace)
    #     assert_invalid_responses(response)

    # def test_ap_enable_false_policy_incorrect(
    #     self, kube_apis, crd_ingress_controller_with_ap, appprotect_setup, test_namespace
    # ):
    #     """
    #     Test malicious script request is working normally while AppProtect is disabled in with incorrect policy in ingress
    #     """
    #     create_ingress_with_ap_annotations(
    #         kube_apis,
    #         src_ing_yaml,
    #         test_namespace,
    #         "invalid-policy",
    #         "False",
    #         "True",
    #         "127.0.0.1:514",
    #     )
    #     ingress_host = get_first_ingress_host_from_yaml(src_ing_yaml)

    #     print(
    #         "--------- Run test while AppProtect module is disabled with incorrect policy ---------"
    #     )

    #     wait_before_test(40)
    #     ensure_response_from_backend(appprotect_setup.req_url, ingress_host)

    #     print("----------------------- Send request ----------------------")
    #     response = requests.get(
    #         appprotect_setup.req_url + "/<script>", headers={"host": ingress_host}, verify=False
    #     )
    #     print(response.text)
    #     delete_items_from_yaml(kube_apis, src_ing_yaml, test_namespace)
    #     assert_valid_responses(response)

    # def test_ap_sec_logs_on(
    #     self, kube_apis, crd_ingress_controller_with_ap, appprotect_setup, test_namespace
    # ):
    #     """
    #     Test corresponding log entries with correct policy (includes setting up a syslog server as defined in syslog.yaml)
    #     """
    #     src_syslog_yaml = f"{TEST_DATA}/appprotect/syslog.yaml"
    #     log_loc = f"/var/log/messages"

    #     create_items_from_yaml(kube_apis, src_syslog_yaml, test_namespace)

    #     wait_before_test(40)
    #     syslog_ep = (
    #         kube_apis.v1.read_namespaced_endpoints("syslog-svc", test_namespace)
    #         .subsets[0]
    #         .addresses[0]
    #         .ip
    #     )

    #     # items[-1] because syslog pod is last one to spin-up
    #     syslog_pod = kube_apis.v1.list_namespaced_pod(test_namespace).items[-1].metadata.name

    #     create_ingress_with_ap_annotations(
    #         kube_apis, src_ing_yaml, test_namespace, ap_policy, "True", "True", f"{syslog_ep}:514"
    #     )
    #     ingress_host = get_first_ingress_host_from_yaml(src_ing_yaml)

    #     print("--------- Run test while AppProtect module is enabled with correct policy ---------")

    #     wait_before_test(40)
    #     ensure_response_from_backend(appprotect_setup.req_url, ingress_host)

    #     print("----------------------- Send invalid request ----------------------")
    #     response = requests.get(
    #         appprotect_setup.req_url + "/<script>", headers={"host": ingress_host}, verify=False
    #     )
    #     print(response.text)
    #     wait_before_test(5)
    #     log_contents = get_file_contents(kube_apis.v1, log_loc, syslog_pod, test_namespace)

    #     assert_invalid_responses(response)
    #     assert (
    #         f'ASM:attack_type="Non-browser Client,Abuse of Functionality,Cross Site Scripting (XSS)"'
    #         in log_contents
    #     )
    #     assert f'severity="Critical"' in log_contents
    #     assert f'request_status="blocked"' in log_contents
    #     assert f'outcome="REJECTED"' in log_contents

    #     print("----------------------- Send valid request ----------------------")
    #     headers = {
    #         "Host": ingress_host,
    #         "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0",
    #     }
    #     response = requests.get(appprotect_setup.req_url, headers=headers, verify=False)
    #     print(response.text)
    #     wait_before_test(5)
    #     log_contents = get_file_contents(kube_apis.v1, log_loc, syslog_pod, test_namespace)

    #     delete_items_from_yaml(kube_apis, src_ing_yaml, test_namespace)
    #     delete_items_from_yaml(kube_apis, src_syslog_yaml, test_namespace)

    #     assert_valid_responses(response)
    #     assert f'ASM:attack_type="N/A"' in log_contents
    #     assert f'severity="Informational"' in log_contents
    #     assert f'request_status="passed"' in log_contents
    #     assert f'outcome="PASSED"' in log_contents

    # @pytest.mark.smoke
    # def test_ap_enable_true_policy_correct_uds(
    #     self, kube_apis, crd_ingress_controller_with_ap, appprotect_setup, test_namespace
    # ):
    #     """
    #     Test request with UDS rule string is rejected while AppProtect with User Defined Signatures is enabled in Ingress
    #     """

    #     ap_uds_crd_name = get_name_from_yaml(uds_crd)
    #     create_crd_from_yaml(
    #         kube_apis.api_extensions_v1_beta1, ap_uds_crd_name, uds_crd,
    #     )
    #     wait_before_test()

    #     usersig_name = create_ap_usersig_from_yaml(
    #         kube_apis.custom_objects, uds_crd_resource, test_namespace
    #     )
    #     # Apply dataguard-alarm AP policy with UDS
    #     delete_and_create_ap_policy_from_yaml(
    #         kube_apis.custom_objects,
    #         ap_policy,
    #         f"{TEST_DATA}/appprotect/{ap_policy_uds}.yaml",
    #         test_namespace,
    #     )
    #     wait_before_test()

    #     create_ingress_with_ap_annotations(
    #         kube_apis, src_ing_yaml, test_namespace, ap_policy, "True", "True", "127.0.0.1:514"
    #     )
    #     ingress_host = get_first_ingress_host_from_yaml(src_ing_yaml)

    #     print(
    #         "--------- Run test while AppProtect module is enabled with correct policy and UDS ---------"
    #     )

    #     ap_crd_info = read_ap_crd(kube_apis.custom_objects, test_namespace, "appolicies", ap_policy)
    #     assert_ap_crd_info(ap_crd_info, ap_policy)
    #     wait_before_test(120)

    #     ensure_response_from_backend(appprotect_setup.req_url, ingress_host)
    #     print("----------------------- Send request ----------------------")
    #     response = requests.get(
    #         appprotect_setup.req_url, headers={"host": ingress_host}, verify=False, data="kic"
    #     )
    #     print(response.text)

    #     # Restore default dataguard-alarm policy
    #     delete_and_create_ap_policy_from_yaml(
    #         kube_apis.custom_objects,
    #         ap_policy,
    #         f"{TEST_DATA}/appprotect/{ap_policy_uds}.yaml",
    #         test_namespace,
    #     )
    #     delete_ap_usersig(kube_apis.custom_objects, usersig_name, test_namespace)
    #     delete_crd(
    #         kube_apis.api_extensions_v1_beta1, ap_uds_crd_name,
    #     )
    #     delete_items_from_yaml(kube_apis, src_ing_yaml, test_namespace)
    #     assert_invalid_responses(response)
