/*
 * Copyright (C) 2011-2020 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
 /**
  * File: sgx_dcap_quoteverify.cpp
  *
  * Description: Quote Verification Library
  */

#include "sgx_dcap_quoteverify.h"
#include "sgx_dcap_pcs_com.h"
#include "sgx_dcap_qv_internal.h"
#ifndef _MSC_VER
#include "linux/qve_u.h"
#else //_MSC_VER
#include "win/qve_u.h"
#endif //_MSC_VER
#include <stdlib.h>
#include <stdio.h>
#include <sgx_urts.h>
#include "se_trace.h"
#include "se_thread.h"
#include "se_memcpy.h"

#if defined(_MSC_VER)
#include <tchar.h>
bool get_qve_path(TCHAR *p_file_path, size_t buf_size);
#else
#include <limits.h>
#define MAX_PATH PATH_MAX
bool get_qve_path(char *p_file_path, size_t buf_size);

#endif

struct QvE_status {
    se_mutex_t m_qve_mutex;
    sgx_ql_request_policy_t m_qve_enclave_load_policy;
    sgx_enclave_id_t m_qve_eid;
    sgx_misc_attribute_t m_qve_attributes;

    QvE_status() :
        m_qve_enclave_load_policy(SGX_QL_DEFAULT),
        m_qve_eid(0)
    {
        se_mutex_init(&m_qve_mutex);
        //should be replaced with memset_s, but currently can't find proper header file for it
        //
        memset(&m_qve_attributes, 0, sizeof(m_qve_attributes));
    }
    ~QvE_status() {
        if (m_qve_eid != 0) sgx_destroy_enclave(m_qve_eid);
        se_mutex_destroy(&m_qve_mutex);
    }
};

static QvE_status g_qve_status;

static sgx_status_t load_qve(sgx_enclave_id_t *p_qve_eid,
    sgx_misc_attribute_t *p_qve_attributes,
    sgx_launch_token_t *p_launch_token)
{
    sgx_status_t sgx_status = SGX_SUCCESS;
    int enclave_lost_retry_time = 1;
    int launch_token_updated = 0;
#if defined(_MSC_VER)
    TCHAR qve_enclave_path[MAX_PATH] = _T("");
#else
    char qve_enclave_path[MAX_PATH] = "";
#endif
    //should be replaced with memset_s, but currently can't find proper header file for it
    //
    memset(p_launch_token, 0, sizeof(*p_launch_token));

    int rc = se_mutex_lock(&g_qve_status.m_qve_mutex);
    if (rc != 1)
    {
        SE_TRACE(SE_TRACE_ERROR, "Failed to lock mutex");
        return SGX_ERROR_UNEXPECTED; // SGX_QvE_INTERFACE_UNAVAILABLE;
    }

    // Load the QvE
    if (g_qve_status.m_qve_eid == 0)
    {
        if (!get_qve_path(qve_enclave_path, MAX_PATH)) {
            rc = se_mutex_unlock(&g_qve_status.m_qve_mutex);
            if (rc != 1)
            {
                SE_TRACE(SE_TRACE_ERROR, "Failed to unlock mutex");
            }
            return SGX_ERROR_UNEXPECTED; //SGX_QvE_INTERFACE_UNAVAILABLE;
        }
        do
        {
            SE_TRACE(SE_TRACE_DEBUG, "Call sgx_create_enclave for QvE. %s\n", qve_enclave_path);
            sgx_status = sgx_create_enclave(qve_enclave_path,
                0, // Don't support debug load QvE by default
                p_launch_token,
                &launch_token_updated,
                p_qve_eid,
                p_qve_attributes);
            if (SGX_SUCCESS != sgx_status)
            {
                SE_TRACE(SE_TRACE_ERROR, "Error, call sgx_create_enclave for QvE fail [%s], SGXError:%04x.\n", __FUNCTION__, sgx_status);
            }

            // Retry in case there was a power transition that resulted is losing the enclave.
        } while (SGX_ERROR_ENCLAVE_LOST == sgx_status && enclave_lost_retry_time--);
        if (sgx_status != SGX_SUCCESS)
        {
            rc = se_mutex_unlock(&g_qve_status.m_qve_mutex);
            if (rc != 1)
            {
                SE_TRACE(SE_TRACE_ERROR, "Failed to unlock mutex");
                return SGX_ERROR_UNEXPECTED; //SGX_QvE_INTERFACE_UNAVAILABLE;
            }
            if (sgx_status == SGX_ERROR_OUT_OF_EPC)
                return SGX_ERROR_OUT_OF_EPC;
            else
                return SGX_ERROR_UNEXPECTED; //SGX_QvE_INTERFACE_UNAVAILABLE;
        }
        g_qve_status.m_qve_eid = *p_qve_eid;
        memcpy_s(&g_qve_status.m_qve_attributes, sizeof(sgx_misc_attribute_t), p_qve_attributes, sizeof(sgx_misc_attribute_t));
    }
    else {
        *p_qve_eid = g_qve_status.m_qve_eid;
        memcpy_s(p_qve_attributes, sizeof(sgx_misc_attribute_t), &g_qve_status.m_qve_attributes, sizeof(sgx_misc_attribute_t));
    }
    rc = se_mutex_unlock(&g_qve_status.m_qve_mutex);
    if (rc != 1)
    {
        SE_TRACE(SE_TRACE_ERROR, "Failed to unlock mutex");
        return SGX_ERROR_UNEXPECTED;
    }
    return SGX_SUCCESS;
}

static void unload_qve(bool force = false)
{
    int rc = se_mutex_lock(&g_qve_status.m_qve_mutex);
    if (rc != 1)
    {
        SE_TRACE(SE_TRACE_ERROR, "Failed to lock mutex");
        return;
    }

    // Unload the QvE enclave
    if (g_qve_status.m_qve_eid &&
        (force || g_qve_status.m_qve_enclave_load_policy != SGX_QL_PERSISTENT)
        )
    {
        SE_TRACE(SE_TRACE_DEBUG, "unload qve enclave 0X%llX\n", g_qve_status.m_qve_eid);
        sgx_destroy_enclave(g_qve_status.m_qve_eid);
        g_qve_status.m_qve_eid = 0;
        memset(&g_qve_status.m_qve_attributes, 0, sizeof(g_qve_status.m_qve_attributes));
    }

    rc = se_mutex_unlock(&g_qve_status.m_qve_mutex);
    if (rc != 1)
    {
        SE_TRACE(SE_TRACE_ERROR, "Failed to unlock mutex");
        return;
    }
}

quote3_error_t sgx_qv_set_enclave_load_policy(
    sgx_ql_request_policy_t policy)
{
    if (policy > SGX_QL_EPHEMERAL)
        return SGX_QL_UNSUPPORTED_LOADING_POLICY;
    g_qve_status.m_qve_enclave_load_policy = policy;
    if (policy == SGX_QL_EPHEMERAL)
        unload_qve(true);
    return SGX_QL_SUCCESS;
}


/* Initialize the enclave:
 * Call sgx_create_enclave to initialize an enclave instance
 **/
static int initialize_enclave(sgx_enclave_id_t* eid)
{
    sgx_launch_token_t token = { 0 };
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    sgx_misc_attribute_t p_mist_attribute;
    ret = load_qve(eid, &p_mist_attribute, &token);
    if (ret != SGX_SUCCESS) {
        return -1;
    }

    return 0;
}


/**
 * Perform quote verification. This API will load QvE and call the verification Ecall.
 **/

quote3_error_t sgx_qv_verify_quote(
    const uint8_t *p_quote,
    uint32_t quote_size,
    const struct _sgx_ql_qve_collateral_t *p_quote_collateral,
    const time_t expiration_check_date,
    uint32_t *p_collateral_expiration_status,
    sgx_ql_qv_result_t *p_quote_verification_result,
    sgx_ql_qe_report_info_t *p_qve_report_info,
    uint32_t supplemental_data_size,
    uint8_t *p_supplemental_data) {
    //validate input parameters
    //
    if (CHECK_MANDATORY_PARAMS(p_quote, quote_size) ||
        NULL_POINTER(p_collateral_expiration_status) ||
        expiration_check_date == 0 ||
        NULL_POINTER(p_quote_verification_result) ||
        CHECK_OPT_PARAMS(p_supplemental_data, supplemental_data_size)) {
        //one or more invalid parameters
        //
        if (p_quote_verification_result) {
            *p_quote_verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;
        }
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }

    //validate supplemental data size
    //
    if (p_supplemental_data) {
        quote3_error_t tmp_ret = SGX_QL_ERROR_UNEXPECTED;
        uint32_t tmp_size = 0;
        tmp_ret = sgx_qv_get_quote_supplemental_data_size(&tmp_size);

        if (tmp_ret != SGX_QL_SUCCESS || tmp_size > supplemental_data_size) {

            if (p_quote_verification_result) {
                *p_quote_verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;
            }
            return SGX_QL_ERROR_INVALID_PARAMETER;
        }
    }

    sgx_enclave_id_t qve_eid = 0;
    quote3_error_t qve_ret = SGX_QL_ERROR_UNEXPECTED;
    sgx_status_t ecall_ret = SGX_ERROR_UNEXPECTED;
    unsigned char fmspc_from_quote[FMSPC_SIZE] = { 0 };
    unsigned char ca_from_quote[CA_SIZE] = { 0 };
    struct _sgx_ql_qve_collateral_t* qve_collaterals_from_qp = NULL;


    //decide trusted VS untrusted verification
    //
    if (p_qve_report_info) {
        do {
            //create and initialize QvE
            //
            if (initialize_enclave(&qve_eid) == -1) {
                qve_ret = SGX_QL_ENCLAVE_LOAD_ERROR;
                break;
            }

            //in case input collateral is NULL, dynamically load and call QPL to retrieve verification collateral
            //
            if (NULL_POINTER(p_quote_collateral)) {

                //call QvE to extract fmspc and CA from the quote, these values are required inorder to query collateral from QPL
                //
                ecall_ret = get_fmspc_ca_from_quote(qve_eid, &qve_ret, p_quote, quote_size, fmspc_from_quote, FMSPC_SIZE, ca_from_quote, CA_SIZE);
                if (qve_ret == SGX_QL_SUCCESS && ecall_ret == SGX_SUCCESS) {
                    SE_TRACE(SE_TRACE_DEBUG, "Info: get_fmspc_ca_from_quote successfully returned.\n");
                }
                else {
                    SE_TRACE(SE_TRACE_DEBUG, "Error: get_fmspc_ca_from_quote failed: 0x%04x\n", qve_ret);
                    break;
                }

                //retrieve verification collateral using QPL
                //
                qve_ret = sgx_dcap_retrieve_verification_collateral(
                    (const char *)fmspc_from_quote,
                    FMSPC_SIZE,
                    (const char *)ca_from_quote,
                    &qve_collaterals_from_qp);
                if (qve_ret == SGX_QL_SUCCESS) {
                    SE_TRACE(SE_TRACE_DEBUG, "Info: sgx_dcap_retrieve_verification_collateral successfully returned.\n");
                }
                else {
                    SE_TRACE(SE_TRACE_DEBUG, "Error: sgx_dcap_retrieve_verification_collateral failed: 0x%04x\n", qve_ret);
                    break;
                }
                p_quote_collateral = qve_collaterals_from_qp;
            }

            ecall_ret = sgx_qve_verify_quote(
                qve_eid, &qve_ret,
                p_quote, quote_size,
                p_quote_collateral,
                expiration_check_date,
                p_collateral_expiration_status,
                p_quote_verification_result,
                p_qve_report_info,
                supplemental_data_size,
                p_supplemental_data);
            if (qve_ret == SGX_QL_SUCCESS && ecall_ret == SGX_SUCCESS) {
                SE_TRACE(SE_TRACE_DEBUG, "Info: QvE: sgx_qve_verify_quote successfully returned.\n");
            }
            else {
                SE_TRACE(SE_TRACE_DEBUG, "Error: QvE: sgx_qve_verify_quote failed: 0x%04x\n", qve_ret);
                break;
            }

        } while (0);

        //destroy QvE enclave
        //
        if (qve_eid != 0) {
            unload_qve();
        }
    }
    else {
        do {
            //in case input collateral is NULL, dynamically load and call QPL to retrieve verification collateral
            //
            if (NULL_POINTER(p_quote_collateral)) {

                //extract fmspc and CA from the quote, these values are required inorder to query collateral from QPL
                //
                qve_ret = qvl_get_fmspc_ca_from_quote(p_quote, quote_size, fmspc_from_quote, FMSPC_SIZE, ca_from_quote, CA_SIZE);
                if (qve_ret == SGX_QL_SUCCESS) {
                    SE_TRACE(SE_TRACE_DEBUG, "Info: get_fmspc_ca_from_quote successfully returned.\n");
                }
                else {
                    SE_TRACE(SE_TRACE_DEBUG, "Error: get_fmspc_ca_from_quote failed: 0x%04x\n", qve_ret);
                    break;
                }

                //retrieve verification collateral using QPL
                //
                qve_ret = sgx_dcap_retrieve_verification_collateral(
                    (const char *)fmspc_from_quote,
                    FMSPC_SIZE,
                    (const char *)ca_from_quote,
                    &qve_collaterals_from_qp);
                if (qve_ret == SGX_QL_SUCCESS) {
                    SE_TRACE(SE_TRACE_DEBUG, "Info: sgx_dcap_retrieve_verification_collateral successfully returned.\n");
                }
                else {
                    SE_TRACE(SE_TRACE_DEBUG, "Error: sgx_dcap_retrieve_verification_collateral failed: 0x%04x\n", qve_ret);
                    break;
                }
                p_quote_collateral = qve_collaterals_from_qp;
            }
            qve_ret = sgx_qvl_verify_quote(
                p_quote, quote_size,
                p_quote_collateral,
                expiration_check_date,
                p_collateral_expiration_status,
                p_quote_verification_result,
                p_qve_report_info,
                supplemental_data_size,
                p_supplemental_data);

            if (qve_ret == SGX_QL_SUCCESS) {
                SE_TRACE(SE_TRACE_DEBUG, "Info: QVL: sgx_qve_verify_quote successfully returned.\n");
            }
            else {
                SE_TRACE(SE_TRACE_DEBUG, "Error: QVL: sgx_qve_verify_quote failed: 0x%04x\n", qve_ret);
                break;
            }
        } while (0);
    }
    //free verification collateral using QPL
    //
    if (qve_collaterals_from_qp) {
        sgx_dcap_free_verification_collateral(qve_collaterals_from_qp);
    }


    return qve_ret;
}

/**
 * Get supplemental data required size.
 **/
quote3_error_t sgx_qv_get_quote_supplemental_data_size(
    uint32_t *p_data_size) {
    if (NULL_POINTER(p_data_size)) {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }
    uint32_t trusted_version = 0, untrusted_version = 0;
    uint32_t trusted_size = 0, untrusted_size = 0;
    bool VerNumMismatch = false;
    sgx_status_t ecall_ret = SGX_ERROR_UNEXPECTED;
    sgx_enclave_id_t qve_eid = 0;
    quote3_error_t qve_ret = SGX_QL_ERROR_INVALID_PARAMETER;

    do {
        //create and initialize QvE
        //
        if (initialize_enclave(&qve_eid) == -1) {
            qve_ret = SGX_QL_ENCLAVE_LOAD_ERROR;
            break;
        }

        //if QvE has been loaded, any ECALL failure would treat as an error
        //
        VerNumMismatch = true;

        //call QvE ECALL to get supplemental data version
        //
        ecall_ret = sgx_qve_get_quote_supplemental_data_version(qve_eid, &qve_ret, &trusted_version);
        if (qve_ret == SGX_QL_SUCCESS && ecall_ret == SGX_SUCCESS) {
            SE_TRACE(SE_TRACE_DEBUG, "Info: sgx_qve_get_quote_supplemental_data_version successfully returned.\n");
        }
        else {
            SE_TRACE(SE_TRACE_DEBUG, "Error: sgx_qve_get_quote_supplemental_data_version failed: 0x%04x\n", qve_ret);
            trusted_version = 0;
            break;
        }

        ecall_ret = sgx_qve_get_quote_supplemental_data_size(qve_eid, &qve_ret, &trusted_size);
        if (qve_ret == SGX_QL_SUCCESS && ecall_ret == SGX_SUCCESS) {
            SE_TRACE(SE_TRACE_DEBUG, "Info: sgx_qve_get_quote_supplemental_data_size successfully returned.\n");
        }
        else {
            SE_TRACE(SE_TRACE_DEBUG, "Error: sgx_qve_get_quote_supplemental_data_size failed: 0x%04x\n", qve_ret);
            trusted_size = 0;
            break;
        }


    } while (0);


    do {
        //call untrusted API to get supplemental data version
        //
        qve_ret = sgx_qvl_get_quote_supplemental_data_version(&untrusted_version);
        if (qve_ret != SGX_QL_SUCCESS) {
            SE_TRACE(SE_TRACE_DEBUG, "Error: untrusted API sgx_qvl_get_quote_supplemental_data_version failed: 0x%04x\n", qve_ret);
            *p_data_size = 0;
            break;
        }

        //call untrusted API to get supplemental data size
        //
        qve_ret = sgx_qvl_get_quote_supplemental_data_size(&untrusted_size);
        if (qve_ret != SGX_QL_SUCCESS) {
            SE_TRACE(SE_TRACE_DEBUG, "Error: untrusted API sgx_qvl_get_quote_supplemental_data_size failed: 0x%04x\n", qve_ret);
            *p_data_size = 0;
            break;
        }

        if (VerNumMismatch) {
            if (trusted_version != untrusted_version || trusted_size != untrusted_size) {
                SE_TRACE(SE_TRACE_DEBUG, "Error: Quote supplemental data version is different between trusted QvE and untrusted QVL.\n");
                *p_data_size = 0;
                qve_ret = SGX_QL_ERROR_QVL_QVE_MISMATCH;
                break;
            }
        }

        *p_data_size = untrusted_size;

    } while (0) ;


    //destroy QvE enclave
    //
    if (qve_eid != 0) {
        unload_qve();
    }

    return qve_ret;
}


/**
 * Get QvE identity and Root CA CRL
 **/
quote3_error_t sgx_qv_get_qve_identity(
         uint8_t **pp_qveid,
         uint32_t *p_qveid_size,
         uint8_t **pp_qveid_issue_chain,
         uint32_t *p_qveid_issue_chain_size,
         uint8_t **pp_root_ca_crl,
         uint16_t *p_root_ca_crl_size) {

    return sgx_dcap_retrieve_qve_identity(pp_qveid,
                                          p_qveid_size,
                                          pp_qveid_issue_chain,
                                          p_qveid_issue_chain_size,
                                          pp_root_ca_crl,
                                          p_root_ca_crl_size);
}


/**
 * Free QvE identity and Root CA CRL
 **/
quote3_error_t sgx_qv_free_qve_identity(
        uint8_t *p_qveid,
        uint8_t *p_qveid_issue_chain,
        uint8_t *p_root_ca_crl) {

    return sgx_dcap_free_qve_identity(p_qveid,
                                      p_qveid_issue_chain,
                                      p_root_ca_crl);
}
#ifndef _MSC_VER

#include <sys/types.h>
#include <sys/stat.h>


/**
 * This API can be used to set the full path of QVE and QPL library.
 *
 * The function takes the enum and the corresponding full path.
 *
 * @param path_type The type of binary being passed in.
 * @param p_path It should be a valid full path.
 *
 * @return SGX_QL_SUCCESS  Successfully set the full path.
 * @return SGX_QL_ERROR_INVALID_PARAMETER p_path is not a valid full path or the path is too long.
 */

quote3_error_t sgx_qv_set_path(
        sgx_qv_path_type_t path_type,
        const char *p_path)
{
    quote3_error_t ret = SGX_QL_SUCCESS;
    bool temp_ret = false;
    struct stat info;

    if (!p_path)
        return(SGX_QL_ERROR_INVALID_PARAMETER);

    if(stat(p_path, &info) != 0)
        return(SGX_QL_ERROR_INVALID_PARAMETER);
    else if((info.st_mode & S_IFREG) == 0)
        return(SGX_QL_ERROR_INVALID_PARAMETER);

    switch(path_type)
    {
        case SGX_QV_QVE_PATH:
            temp_ret = sgx_qv_set_qve_path(p_path);
            ret = temp_ret ? SGX_QL_SUCCESS : SGX_QL_ERROR_INVALID_PARAMETER;
            break;
        case SGX_QV_QPL_PATH:
            temp_ret = sgx_qv_set_qpl_path(p_path);
            ret = temp_ret ? SGX_QL_SUCCESS : SGX_QL_ERROR_INVALID_PARAMETER;
            break;
    default:
        ret = SGX_QL_ERROR_INVALID_PARAMETER;
        break;
    }
    return(ret);
}
#endif
