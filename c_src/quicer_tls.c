/*--------------------------------------------------------------------
Copyright (c) 2023-2024 EMQ Technologies Co., Ltd. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-------------------------------------------------------------------*/
#include "quicer_tls.h"

static bool
load_pkcs12_cert(ErlNifEnv *env,
                 ERL_NIF_TERM opts,
                 QUIC_CREDENTIAL_CONFIG *config)
{
  if (!config)
    {
      return false;
    }

  ERL_NIF_TERM pkcs12_term;
  ErlNifBinary pkcs12_bin;
  if (!enif_get_map_value(env, opts, ATOM_PKCS12_BUNDLE, &pkcs12_term))
    {
      return false;
    }

  if (!enif_inspect_binary(env, pkcs12_term, &pkcs12_bin))
    {
      return false;
    }

  QUIC_CERTIFICATE_PKCS12 *mem_cert
      = CXPLAT_ALLOC_NONPAGED(sizeof(*mem_cert), QUICER_CERTIFICATE_PKCS12);
  if (!mem_cert)
    {
      return false;
    }

  char *blob_copy
      = CXPLAT_ALLOC_NONPAGED(pkcs12_bin.size, QUICER_PKCS12_BUNDLE);
  if (!blob_copy)
    {
      CXPLAT_FREE(mem_cert, QUICER_CERTIFICATE_PKCS12);
      return false;
    }

  CxPlatCopyMemory(blob_copy, pkcs12_bin.data, pkcs12_bin.size);

  mem_cert->Asn1Blob = (const uint8_t *)blob_copy;
  mem_cert->Asn1BlobLength = pkcs12_bin.size;
  mem_cert->PrivateKeyPassword = NULL;

  config->CertificatePkcs12 = mem_cert;
  config->Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_PKCS12;

  return true;
}

/*
** Build QUIC_CREDENTIAL_CONFIG from options, certfile, keyfile and password
*/
BOOLEAN
parse_cert_options_file(ErlNifEnv *env,
                        ERL_NIF_TERM options,
                        QUIC_CREDENTIAL_CONFIG *CredConfig)
{
  if (!CredConfig)
    {
      return false;
    }

  char *cert_path
      = str_from_map(env, ATOM_CERTFILE, &options, NULL, PATH_MAX + 1);
  char *key_path = str_from_map(env, ATOM_KEYFILE, &options, NULL, PATH_MAX + 1);
  char *pwd = NULL;

  if (!cert_path || !key_path)
    {
      goto cleanup;
    }

  ERL_NIF_TERM pwd_term;
  if (enif_get_map_value(env, options, ATOM_PASSWORD, &pwd_term))
    {
      pwd = str_from_map(env, ATOM_PASSWORD, &options, NULL, 256);
      if (!pwd)
        {
          goto cleanup;
        }

      QUIC_CERTIFICATE_FILE_PROTECTED *cert
          = CXPLAT_ALLOC_NONPAGED(sizeof(*cert), QUICER_CERTIFICATE_FILE);

      if (!cert)
        {
          goto cleanup;
        }

      cert->CertificateFile = cert_path;
      cert->PrivateKeyFile = key_path;
      cert->PrivateKeyPassword = pwd;

      CredConfig->CertificateFileProtected = cert;
      CredConfig->Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED;
    }
  else
    {
      QUIC_CERTIFICATE_FILE *cert
          = CXPLAT_ALLOC_NONPAGED(sizeof(*cert), QUICER_CERTIFICATE_FILE);

      if (!cert)
        {
          goto cleanup;
        }

      cert->CertificateFile = cert_path;
      cert->PrivateKeyFile = key_path;

      CredConfig->CertificateFile = cert;
      CredConfig->Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
    }

  return true;

cleanup:
  free(cert_path);
  free(key_path);
  free(pwd);
  return false;
}

BOOLEAN
parse_cert_options(ErlNifEnv *env,
                   ERL_NIF_TERM options,
                   QUIC_CREDENTIAL_CONFIG *CredConfig)
{
  if (!CredConfig)
    {
      return false;
    }

  char *cert_path
      = str_from_map(env, ATOM_CERTFILE, &options, NULL, PATH_MAX + 1);
  char *key_path = str_from_map(env, ATOM_KEYFILE, &options, NULL, PATH_MAX + 1);

  bool ok = false;

  if (cert_path && key_path)
    {
      ok = parse_cert_options_file(env, options, CredConfig);
    }
  else
    {
      ERL_NIF_TERM pkcs12_term;
      if (enif_get_map_value(env, options, ATOM_PKCS12_BUNDLE, &pkcs12_term)
          && enif_is_binary(env, pkcs12_term))
        {
          ok = load_pkcs12_cert(env, options, CredConfig);
        }
    }

  free(cert_path);
  free(key_path);
  return ok;
}

/*
 * Parse verify option for listener (server)
 *  verify : boolean() | undefined
 *  output *is_verify if is_verify is not NULL
 */
BOOLEAN
parse_verify_options(ErlNifEnv *env,
                     ERL_NIF_TERM options,
                     QUIC_CREDENTIAL_CONFIG *CredConfig,
                     BOOLEAN is_server,
                     _Out_ BOOLEAN *is_verify)
{

  BOOLEAN verify = load_verify(env, &options, FALSE);

  if (is_verify)
    {
      *is_verify = verify;
    }

  // always indicate that we received a certificate
  CredConfig->Flags |= QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED;

  if (is_server)
    {
      // require client certificate always => this means both side are required
      // to send a certificate
      CredConfig->Flags |= QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION;
    }

  if (!verify)
    {
      // verify :none or :verify_none => no certificate validation
      CredConfig->Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
    }
  else
    {
      // Verify peer is enabled
      if (!is_server)
        {
          ERL_NIF_TERM tmp;
          if (enif_get_map_value(env, options, ATOM_CACERTFILE, &tmp))
            {
#if defined(QUICER_USE_TRUSTED_STORE)
              // cacertfile is set, use it for self validation.
              CredConfig->Flags
                  |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
#else
              // cacertfile is set, use it for OpenSSL validation.
              CredConfig->Flags
                  |= QUIC_CREDENTIAL_FLAG_SET_CA_CERTIFICATE_FILE;
              CredConfig->CaCertificateFile = str_from_map(
                  env, ATOM_CACERTFILE, &options, NULL, PATH_MAX + 1);
#endif // QUICER_USE_TRUSTED_STORE
              CredConfig->Flags
                  |= QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED;
            }
          CredConfig->Flags
              |= QUIC_CREDENTIAL_FLAG_USE_TLS_BUILTIN_CERTIFICATE_VALIDATION;
        }
    }
  return TRUE;
}

/*
** Parse optional cacertfile option
** @NOTE we alloc buffer for cacertfile, caller should free it
*/
BOOLEAN
parse_cacertfile_option(ErlNifEnv *env,
                        ERL_NIF_TERM options,
                        char **cacertfile)
{
  ERL_NIF_TERM ecacertfile;
  char *tmp = NULL;

  if (!enif_is_map(env, options))
    {
      return FALSE;
    }

  if (enif_get_map_value(env, options, ATOM_CACERTFILE, &ecacertfile))
    {
      tmp = str_from_map(env, ATOM_CACERTFILE, &options, NULL, PATH_MAX + 1);
      if (!tmp)
        {
          return FALSE;
        }
    }
  *cacertfile = tmp;
  return TRUE;
}

#if defined(QUICER_USE_TRUSTED_STORE)
BOOLEAN
build_trustedstore(const char *cacertfile, X509_STORE **trusted_store)
{
  X509_STORE *store = NULL;
  X509_LOOKUP *lookup = NULL;

  if (cacertfile == NULL)
    {
      return FALSE;
    }

  store = X509_STORE_new();
  if (store == NULL)
    {
      return FALSE;
    }

  lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
  if (lookup == NULL)
    {
      X509_STORE_free(store);
      return FALSE;
    }

  if (!X509_LOOKUP_load_file(lookup, cacertfile, X509_FILETYPE_PEM))
    {
      X509_STORE_free(store);
      return FALSE;
    }

  *trusted_store = store;
  return TRUE;
}
#endif // QUICER_USE_TRUSTED_STORE

void
free_certificate(QUIC_CREDENTIAL_CONFIG *cc)
{
  if (!cc)
    {
      return;
    }

  if (QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE == cc->Type)
    {
      free((char *)cc->CertificateFile->CertificateFile);
      free((char *)cc->CertificateFile->PrivateKeyFile);
      CxPlatFree(cc->CertificateFile, QUICER_CERTIFICATE_FILE);
      cc->CertificateFile = NULL;
    }
  else if (QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED == cc->Type)
    {
      free((char *)cc->CertificateFileProtected->CertificateFile);
      free((char *)cc->CertificateFileProtected->PrivateKeyFile);
      free((char *)cc->CertificateFileProtected->PrivateKeyPassword);
      CxPlatFree(cc->CertificateFileProtected,
                 QUICER_CERTIFICATE_FILE_PROTECTED);
      cc->CertificateFileProtected = NULL;
    }

  if (cc->CaCertificateFile)
    {
      free((char *)cc->CaCertificateFile);
      cc->CaCertificateFile = NULL;
    }
}

/*
 * Parse 'sslkeylogfile' option and set QUIC_PARAM_CONN_TLS_SECRETS conn
 * options for sslkeylogfile dump.
 *
 * alloc and update:
 * c_ctx->TlsSecrets = TlsSecrets;
 * c_ctx->ssl_keylogfile = keylogfile;
 *
 * usually they are not inuse (NULL), so we use heap memory.
 * Caller should ensure they are freed after use.
 *
 */
void
parse_sslkeylogfile_option(ErlNifEnv *env,
                           ERL_NIF_TERM eoptions,
                           QuicerConnCTX *c_ctx)
{

  char *keylogfile
      = str_from_map(env, ATOM_SSL_KEYLOGFILE_NAME, &eoptions, NULL, PATH_MAX);

  if (!keylogfile)
    {
      return;
    }
  set_conn_sslkeylogfile(c_ctx, keylogfile);
}

void
set_conn_sslkeylogfile(QuicerConnCTX *c_ctx, char *keylogfile)
{
  QUIC_STATUS Status;

  // Allocate the TLS secrets
  QUIC_TLS_SECRETS *TlsSecrets
      = CXPLAT_ALLOC_NONPAGED(sizeof(QUIC_TLS_SECRETS), QUICER_TLS_SECRETS);

  if (!TlsSecrets)
    {
      return;
    }

  CxPlatZeroMemory(TlsSecrets, sizeof(QUIC_TLS_SECRETS));

  // Set conn opt QUIC_PARAM_CONN_TLS_SECRETS
  if (QUIC_FAILED(Status = MsQuic->SetParam(c_ctx->Connection,
                                            QUIC_PARAM_CONN_TLS_SECRETS,
                                            sizeof(QUIC_TLS_SECRETS),
                                            TlsSecrets)))
    {
      // unlikely
      CXPLAT_FREE(keylogfile, QUICER_TRACE);
      keylogfile = NULL;
      CXPLAT_FREE(TlsSecrets, QUICER_TLS_SECRETS);
      TlsSecrets = NULL;
      fprintf(stderr,
              "failed to enable secret logging: %s",
              QuicStatusToString(Status));
    }

  // @TODO: check if old ssl_keylogfile/TlsSecrets is set, free it?
  c_ctx->TlsSecrets = TlsSecrets;
  c_ctx->ssl_keylogfile = keylogfile;
}

/*
** Convert eterm options (a map) to QUIC_CREDENTIAL_CONFIG
**
** @NOTE We zero reset CredConfig
** @NOTE Also build trusted store if needed
*/
ERL_NIF_TERM
eoptions_to_cred_config(ErlNifEnv *env,
                        ERL_NIF_TERM eoptions,
                        QUIC_CREDENTIAL_CONFIG *CredConfig,
                        X509_STORE **trusted_store)
{
  BOOLEAN is_verify = FALSE;
  char *cacertfile = NULL;
  ERL_NIF_TERM ret = ATOM_OK;

  CXPLAT_FRE_ASSERT(CredConfig);

#if defined(QUICER_USE_TRUSTED_STORE)
  CXPLAT_FRE_ASSERT(trusted_store);
#else
  CXPLAT_FRE_ASSERT(trusted_store == NULL);
#endif // QUICER_USE_TRUSTED_STORE

  CxPlatZeroMemory(CredConfig, sizeof(QUIC_CREDENTIAL_CONFIG));

  CredConfig->Flags = QUIC_CREDENTIAL_FLAG_NONE;

  // Handle the certificate, key, password options
  if (!parse_cert_options(env, eoptions, CredConfig))
    {
      ret = ATOM_QUIC_TLS;
      goto exit;
    }

  // Handle the `verify` options
  if (!parse_verify_options(env, eoptions, CredConfig, TRUE, &is_verify))
    {
      ret = ATOM_VERIFY;
      goto exit;
      ;
    }

  // Hanlde the `cacertfile` options
  if (!parse_cacertfile_option(env, eoptions, &cacertfile))
    {
      // TLS opt error not file content error
      ret = ATOM_CACERTFILE;
      goto exit;
    }

  // Set flags for certificate verification
  if (is_verify && cacertfile)
    { // === START of verify peer with cacertfile === //

      CredConfig->Flags |= QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED;

#if defined(QUICER_USE_TRUSTED_STORE)
      // We do our own verification with the cacert in trusted_store
      // @see QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED
      CredConfig->Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
      if (!build_trustedstore(cacertfile, trusted_store))
        {
          ret = ATOM_CERT_ERROR;
          goto exit;
        }
      free(cacertfile);
      cacertfile = NULL;
#else
      CredConfig->Flags |= QUIC_CREDENTIAL_FLAG_SET_CA_CERTIFICATE_FILE;
      CredConfig->CaCertificateFile = cacertfile;
#if defined(__APPLE__)
      // This seems only needed for macOS
      CredConfig->Flags
          |= QUIC_CREDENTIAL_FLAG_USE_TLS_BUILTIN_CERTIFICATE_VALIDATION;
#endif // __APPLE__
#endif // QUICER_USE_TRUSTED_STORE
    }  // === END of verify peer with cacertfile === //
  else
    { // NO verify peer
#if !defined(QUICER_USE_TRUSTED_STORE)
      CredConfig->Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
#endif // QUICER_USE_TRUSTED_STORE
      // since we don't use cacertfile, free it
      free(cacertfile);
      cacertfile = NULL;
    }
  return ATOM_OK;

exit:
#if defined(QUICER_USE_TRUSTED_STORE)
  free(cacertfile);
  cacertfile = NULL;
#endif // QUICER_USE_TRUSTED_STORE
  free_certificate(CredConfig);
  return ret;
}
