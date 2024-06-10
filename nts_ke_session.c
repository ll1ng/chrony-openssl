/*
  chronyd/chronyc - Programs for keeping computer clocks accurate.

 **********************************************************************
 * Copyright (C) Miroslav Lichvar  2020-2021
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 * 
 **********************************************************************

  =======================================================================

  NTS-KE session used by server and client
  */

#include "config.h"

#include "sysincl.h"

#include "nts_ke_session.h"

#include "conf.h"
#include "local.h"
#include "logging.h"
#include "memory.h"
#include "siv.h"
#include "socket.h"
#include "sched.h"
#include "util.h"

// #include <gnutls/gnutls.h>
// #include <gnutls/x509.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define INVALID_SOCK_FD (-8)

struct RecordHeader {
  uint16_t type;
  uint16_t body_length;
};

struct Message {
  int length;
  int sent;
  int parsed;
  int complete;
  unsigned char data[NKE_MAX_MESSAGE_LENGTH];
};

typedef enum {
  KE_WAIT_CONNECT,
  KE_HANDSHAKE,
  KE_SEND,
  KE_RECEIVE,
  KE_SHUTDOWN,
  KE_STOPPED,
} KeState;

struct NKSN_Instance_Record {
  int server;
  char *server_name;
  NKSN_MessageHandler handler;
  void *handler_arg;

  KeState state;
  int sock_fd;
  char *label;
  // gnutls_session_t tls_session;
  SSL *ssl;

  SCH_TimeoutID timeout_id;
  int retry_factor;

  struct Message message;
  int new_message;
};

typedef struct tlsextalpnctx_st {
    unsigned char *data;
    size_t len;
} tlsextalpnctx;

typedef struct tlsextnextprotoctx_st {
    unsigned char *data;
    size_t len;
    int status;
} tlsextnextprotoctx;

/* ================================================== */

// static gnutls_priority_t priority_cache;

static SSL_CTX *ssl_ctx_s;
static SSL_CTX *ssl_ctx_c;
static int credentials_counter = 0;

static int clock_updates = 0;

unsigned char alpn_name[] = {
  7,'n','t','s','k','e','/','1'
};
static tlsextalpnctx alpn_ctx = { &alpn_name, sizeof(alpn_name)-1 };
static tlsextnextprotoctx next_proto = { &alpn_name, sizeof(alpn_name)-1, -1};
/* ================================================== */

void 
hexdump(const char *pre, void *buf, unsigned int len)
{
  printf("%s\n",pre);
  char *p=(char*)buf;
  for(int i=0;i<len;i++)
  {
    printf("%02x ",((unsigned char*)p)[i]);
  }
  printf("\n");
}

static void
reset_message(struct Message *message)
{
  message->length = 0;
  message->sent = 0;
  message->parsed = 0;
  message->complete = 0;
}

/* ================================================== */

static int
add_record(struct Message *message, int critical, int type, const void *body, int body_length)
{
  struct RecordHeader header;

  assert(message->length <= sizeof (message->data));

  if (body_length < 0 || body_length > 0xffff || type < 0 || type > 0x7fff ||
      message->length + sizeof (header) + body_length > sizeof (message->data))
    return 0;

  header.type = htons(!!critical * NKE_RECORD_CRITICAL_BIT | type);
  header.body_length = htons(body_length);

  memcpy(&message->data[message->length], &header, sizeof (header));
  message->length += sizeof (header);

  if (body_length > 0) {
    memcpy(&message->data[message->length], body, body_length);
    message->length += body_length;
  }

  printf("Record Added:\n");
  printf("Type: 0x%x, Critical Bit: %d\n", type, critical);
  printf("Body Length: %d (0x%x)\n", body_length, body_length);
  printf("Body Content (Hex): ");
  for (int i = 0; i < body_length; ++i) {
      printf("%02x ", ((unsigned char*)body)[i]);
  }
  printf("\n");
  printf("-----------------------------\n");

  return 1;
}

/* ================================================== */

static void
reset_message_parsing(struct Message *message)
{
  message->parsed = 0;
}

/* ================================================== */

static int
get_record(struct Message *message, int *critical, int *type, int *body_length,
           void *body, int buffer_length)
{
  struct RecordHeader header;
  int blen, rlen;

  if (message->length < message->parsed + sizeof (header) ||
      buffer_length < 0)
    return 0;

  memcpy(&header, &message->data[message->parsed], sizeof (header));

  blen = ntohs(header.body_length);
  rlen = sizeof (header) + blen;
  assert(blen >= 0 && rlen > 0);

  if (message->length < message->parsed + rlen)
    return 0;

  if (critical)
    *critical = !!(ntohs(header.type) & NKE_RECORD_CRITICAL_BIT);
  if (type)
    *type = ntohs(header.type) & ~NKE_RECORD_CRITICAL_BIT;
  if (body)
    memcpy(body, &message->data[message->parsed + sizeof (header)], MIN(buffer_length, blen));
  if (body_length)
    *body_length = blen;

  message->parsed += rlen;

  return 1;
}

/* ================================================== */

static int
check_message_format(struct Message *message, int eof)
{
  int critical = 0, type = -1, length = -1, ends = 0;

  reset_message_parsing(message);
  message->complete = 0;

  while (get_record(message, &critical, &type, &length, NULL, 0)) {
    if (type == NKE_RECORD_END_OF_MESSAGE) {
      if (!critical || length != 0 || ends > 0)
        return 0;
      ends++;
    }
  }

  /* If the message cannot be fully parsed, but more data may be coming,
     consider the format to be ok */
  if (message->length == 0 || message->parsed < message->length)
    return !eof;

  if (type != NKE_RECORD_END_OF_MESSAGE)
    return !eof;

  message->complete = 1;

  return 1;
}

/* ================================================== */

static int alpn_cb(SSL *s, const unsigned char **out, unsigned char *outlen,
                   const unsigned char *in, unsigned int inlen, void *arg)
{
    tlsextalpnctx *alpn_ctx = arg;

    // if (!s_quiet) {
    //     /* We can assume that |in| is syntactically valid. */
    //     unsigned int i;
    //     BIO_printf(bio_s_out, "ALPN protocols advertised by the client: ");
    //     for (i = 0; i < inlen;) {
    //         if (i)
    //             BIO_write(bio_s_out, ", ", 2);
    //         BIO_write(bio_s_out, &in[i + 1], in[i]);
    //         i += in[i] + 1;
    //     }
    //     BIO_write(bio_s_out, "\n", 1);
    // }
    LOG(LOGS_INFO,"alpn cb");
    if (SSL_select_next_proto
        ((unsigned char **)out, outlen, alpn_ctx->data, alpn_ctx->len, in,
         inlen) != OPENSSL_NPN_NEGOTIATED) {
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    // if (!s_quiet) {
    //     BIO_printf(bio_s_out, "ALPN protocols selected: ");
    //     BIO_write(bio_s_out, *out, *outlen);
    //     BIO_write(bio_s_out, "\n", 1);
    // }

    return SSL_TLSEXT_ERR_OK;
}

/* ================================================== */

static int next_proto_cb(SSL *s, unsigned char **out, unsigned char *outlen,
                         const unsigned char *in, unsigned int inlen,
                         void *arg)
{
    tlsextnextprotoctx *ctx = arg;
    LOG(LOGS_INFO,"next proto");
    // if (!c_quiet) {
        // /* We can assume that |in| is syntactically valid. */
        // unsigned i;
        // BIO_printf(bio_c_out, "Protocols advertised by server: ");
        // for (i = 0; i < inlen;) {
        //     if (i)
        //         BIO_write(bio_c_out, ", ", 2);
    //         BIO_write(bio_c_out, &in[i + 1], in[i]);
    //         i += in[i] + 1;
    //     }
    //     BIO_write(bio_c_out, "\n", 1);
    // }

    ctx->status =
        SSL_select_next_proto(out, outlen, in, inlen, ctx->data, ctx->len);
    return SSL_TLSEXT_ERR_OK;
}

/* ================================================== */

static SSL*
create_tls_session_s(int server_mode, int client_fd, const char *server_name)
                  //  gnutls_certificate_credentials_t credentials,
                  //  gnutls_priority_t priority

{
  // unsigned char alpn_name[sizeof (NKE_ALPN_NAME)];
  // gnutls_session_t session;
  // gnutls_datum_t alpn;
  // struct sockaddr_in server_addr, client_addr;
  // unsigned int flags;
  int r;
  SSL *ssl;

  // r = gnutls_init(&session, GNUTLS_NONBLOCK | GNUTLS_NO_TICKETS |
  //                 (server_mode ? GNUTLS_SERVER : GNUTLS_CLIENT));
  ssl = SSL_new(ssl_ctx_s);
  if (ssl == NULL)
    LOG(LOGS_ERR,"Error creating SSL server object");
  // if (r < 0) {
  //   LOG(LOGS_ERR, "Could not %s TLS session : %s", "create", gnutls_strerror(r));
  //   return NULL;
  // }
  // 将SSL与套接字关联
  if (SSL_set_fd(ssl, client_fd) == 0)
      LOG(LOGS_ERR,"Error setting SSL file descriptor");
  SSL_set_accept_state(ssl);
  if (!server_mode) {
    assert(server_name);

    if (!UTI_IsStringIP(server_name)) {
      
      // r = gnutls_server_name_set(session, GNUTLS_NAME_DNS, server_name, strlen(server_name));
      // if (r < 0)
      //   goto error;
      //here
    }

    // flags = 0;

    if (clock_updates < CNF_GetNoCertTimeCheck()) {
      // flags |= GNUTLS_VERIFY_DISABLE_TIME_CHECKS | GNUTLS_VERIFY_DISABLE_TRUSTED_TIME_CHECKS;
      DEBUG_LOG("Disabled time checks");
    }

    // gnutls_session_set_verify_cert(session, server_name, flags);
  }

  // r = gnutls_priority_set(session, priority);
  // if (r < 0)
  //   goto error;

  // r = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, credentials);
  // if (r < 0)
  //   goto error;

  // memcpy(alpn_name, NKE_ALPN_NAME, sizeof (alpn_name));
  // alpn.data = alpn_name;
  // alpn.size = sizeof (alpn_name) - 1;

  // r = gnutls_alpn_set_protocols(session, &alpn, 1, 0);
  // if (r < 0)
  //   goto error;
  
  // gnutls_transport_set_int(session, sock_fd);

  return ssl;

error:
  // LOG(LOGS_ERR, "Could not %s TLS session : %s", "set", gnutls_strerror(r));
  LOG(LOGS_ERR, "Could not %s TLS session : %s", "set", "GNU???");
  // gnutls_deinit(session);
  return NULL;
}

static SSL*
create_tls_session_c(int server_mode, int sock_fd, const char *server_name)
                  //  gnutls_certificate_credentials_t credentials,
                  //  gnutls_priority_t priority

{
  // unsigned char alpn_name[sizeof (NKE_ALPN_NAME)];
  // gnutls_session_t session;
  // gnutls_datum_t alpn;
  // struct sockaddr_in server_addr, client_addr;
  // unsigned int flags;
  int r;
  SSL *ssl;

  // r = gnutls_init(&session, GNUTLS_NONBLOCK | GNUTLS_NO_TICKETS |
  //                 (server_mode ? GNUTLS_SERVER : GNUTLS_CLIENT));
  ssl = SSL_new(ssl_ctx_c);
  if (ssl == NULL)
    LOG(LOGS_ERR,"Error creating SSL client object");
  // if (r < 0) {
  //   LOG(LOGS_ERR, "Could not %s TLS session : %s", "create", gnutls_strerror(r));
  //   return NULL;
  // }
  if (SSL_set_fd(ssl, sock_fd) == 0)
      LOG(LOGS_ERR,"Error setting SSL file descriptor");
  SSL_set_connect_state(ssl);
  if (!server_mode) {
    assert(server_name);

    if (!UTI_IsStringIP(server_name)) {
      
      // r = gnutls_server_name_set(session, GNUTLS_NAME_DNS, server_name, strlen(server_name));
      // if (r < 0)
      //   goto error;

    }

    // flags = 0;

    if (clock_updates < CNF_GetNoCertTimeCheck()) {
      // flags |= GNUTLS_VERIFY_DISABLE_TIME_CHECKS | GNUTLS_VERIFY_DISABLE_TRUSTED_TIME_CHECKS;
      DEBUG_LOG("Disabled time checks");
    }

    // gnutls_session_set_verify_cert(session, server_name, flags);
  }

  // r = gnutls_priority_set(session, priority);
  // if (r < 0)
  //   goto error;

  // r = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, credentials);
  // if (r < 0)
  //   goto error;

  // memcpy(alpn_name, NKE_ALPN_NAME, sizeof (alpn_name));
  // alpn.data = alpn_name;
  // alpn.size = sizeof (alpn_name) - 1;

  // r = gnutls_alpn_set_protocols(session, &alpn, 1, 0);
  // if (r < 0)
  //   goto error;

  // gnutls_transport_set_int(session, sock_fd);

  return ssl;

error:
  // LOG(LOGS_ERR, "Could not %s TLS session : %s", "set", gnutls_strerror(r));
  LOG(LOGS_ERR, "Could not %s TLS session : %s", "set", "GNU???");
  // gnutls_deinit(session);

  return NULL;
}

/* ================================================== */

static void
stop_session(NKSN_Instance inst)
{
  if (inst->state == KE_STOPPED)
    return;

  inst->state = KE_STOPPED;

  SSL_free(inst->ssl);
  SCH_RemoveFileHandler(inst->sock_fd);
  SCK_CloseSocket(inst->sock_fd);
    LOG(LOGS_INFO,"close fd=%d",inst->sock_fd);
  inst->sock_fd = INVALID_SOCK_FD;

  Free(inst->label);
  inst->label = NULL;

  // gnutls_deinit(inst->ssl);
  inst->ssl = NULL;

  SCH_RemoveTimeout(inst->timeout_id);
  inst->timeout_id = 0;
}

/* ================================================== */

static void
session_timeout(void *arg)
{
  NKSN_Instance inst = arg;

  LOG(inst->server ? LOGS_DEBUG : LOGS_ERR, "NTS-KE session with %s timed out", inst->label);

  inst->timeout_id = 0;
  stop_session(inst);
}

/* ================================================== */

// static int
// check_alpn(NKSN_Instance inst)
// {
//   gnutls_datum_t alpn;

//   if (gnutls_alpn_get_selected_protocol(inst->tls_session, &alpn) < 0 ||
//       alpn.size != sizeof (NKE_ALPN_NAME) - 1 ||
//       memcmp(alpn.data, NKE_ALPN_NAME, sizeof (NKE_ALPN_NAME) - 1) != 0)
//     return 0;

//   return 1;
// }

static int
check_alpn(NKSN_Instance inst)
{
  // gnutls_datum_t alpn;
  unsigned char *data;
  unsigned int len;

  // if (gnutls_alpn_get_selected_protocol(inst->tls_session, &alpn) < 0 ||
  //     alpn.size != sizeof (NKE_ALPN_NAME) - 1 ||
  //     memcmp(alpn.data, NKE_ALPN_NAME, sizeof (NKE_ALPN_NAME) - 1) != 0)
  //   return 0;
  SSL_get0_alpn_selected(inst->ssl,&data,&len);
  if(len!=sizeof (NKE_ALPN_NAME) - 1||
    memcmp(data, NKE_ALPN_NAME, sizeof (NKE_ALPN_NAME) - 1) != 0)
    return 0;

  return 1;
}

/* ================================================== */

static void
set_input_output(NKSN_Instance inst, int output)
{
  SCH_SetFileHandlerEvent(inst->sock_fd, SCH_FILE_INPUT, !output);
  SCH_SetFileHandlerEvent(inst->sock_fd, SCH_FILE_OUTPUT, output);
}

/* ================================================== */

static void
change_state(NKSN_Instance inst, KeState state)
{
  int output;

  switch (state) {
    case KE_HANDSHAKE:
      output = !inst->server;
      break;
    case KE_WAIT_CONNECT:
    case KE_SEND:
    case KE_SHUTDOWN:
      output = 1;
      break;
    case KE_RECEIVE:
      output = 0;
      break;
    default:
      assert(0);
  }

  set_input_output(inst, output);

  inst->state = state;
}

/* ================================================== */

void printStringInHex(struct Message *message) {
    const unsigned char* p = (const unsigned char*)message->data;
    int len=message->length;
    printf("length=%d\n",len);
    for (int i=0;i<len;i++) {
        printf("%02X ", *p);
        p++;
    }
    printf("\n");
}

void set_bio(SSL *ssl, BIO *bio)
{
  SSL_set_bio(ssl,bio,bio);
}

static int
handle_event(NKSN_Instance inst, int event)
{
  struct Message *message = &inst->message;
  int r;

  DEBUG_LOG("Session event %d fd=%d state=%d", event, inst->sock_fd, (int)inst->state);

  switch (inst->state) {
    case KE_WAIT_CONNECT://client
      /* Check if connect() succeeded */
      if (event != SCH_FILE_OUTPUT)
        return 0;

      /* Get the socket error */
      if (!SCK_GetIntOption(inst->sock_fd, SOL_SOCKET, SO_ERROR, &r))
        r = EINVAL;

      if (r != 0) {
        LOG(LOGS_ERR, "Could not connect to %s : %s", inst->label, strerror(r));
        stop_session(inst);
        return 0;
      }

      DEBUG_LOG("Connected to %s", inst->label);
      LOG(LOGS_INFO,"Connected to %s", inst->label);

      change_state(inst, KE_HANDSHAKE);
      return 0;

    case KE_HANDSHAKE:
      // r = gnutls_handshake(inst->tls_session);      
      // SSL 对象是非阻塞的
      LOG(LOGS_INFO,"handshaking...\nBLOBK=%ld",SSL_get_mode(inst->ssl) & SSL_MODE_ENABLE_PARTIAL_WRITE);

      r=SSL_do_handshake(inst->ssl);
      
      if(r!=1)//return -1
      {
        if(ERR_FATAL_ERROR(r)){
          LOG(LOGS_INFO,"ERRString=%s r=%d",ERR_reason_error_string(SSL_get_error(inst->ssl,r)),SSL_get_error(inst->ssl,r));
          LOG(LOGS_ERR,"Error performing SSL handshake");
          stop_session(inst);
          return 0;
        }
        // set_input_output(inst->ssl,SSL_get_rbio(inst->ssl)!=NULL?0:1);
        return 0;
      }

      // if (r < 0) {
      //   if (gnutls_error_is_fatal(r)) {
      //     gnutls_datum_t cert_error;

          /* Get a description of verification errors */
          // if (r != GNUTLS_E_CERTIFICATE_VERIFICATION_ERROR ||
          //     gnutls_certificate_verification_status_print(
          //                 gnutls_session_get_verify_cert_status(inst->tls_session),
          //                 gnutls_certificate_type_get(inst->tls_session), &cert_error, 0) < 0)
          //   cert_error.data = NULL;

          // LOG(inst->server ? LOGS_DEBUG : LOGS_ERR,
          //     "TLS handshake with %s failed : %s%s%s", inst->label, gnutls_strerror(r),
          //     cert_error.data ? " " : "", cert_error.data ? (const char *)cert_error.data : "");

          // if (cert_error.data)
          //   gnutls_free(cert_error.data);

          // stop_session(inst);

          /* Increase the retry interval if the handshake did not fail due
             to the other end closing the connection */
          // if (r != GNUTLS_E_PULL_ERROR && r != GNUTLS_E_PREMATURE_TERMINATION)
          //   inst->retry_factor = NKE_RETRY_FACTOR2_TLS;

          // return 0;
        // }

        /* Disable output when the handshake is trying to receive data */
        // set_input_output(inst, gnutls_record_get_direction(inst->tls_session));
        // return 0;
      // }

      inst->retry_factor = NKE_RETRY_FACTOR2_TLS;

      if (DEBUG) {
        // char *description = gnutls_session_get_desc(inst->tls_session);
        char *description=NULL;
        DEBUG_LOG("Handshake with %s completed %s",
                  inst->label, description ? description : "");
        // gnutls_free(description);
      }

      if (!check_alpn(inst)) {
        LOG(inst->server ? LOGS_DEBUG : LOGS_ERR, "NTS-KE not supported by %s", inst->label);
        stop_session(inst);
        return 0;
      }

      /* Client will send a request to the server */
      change_state(inst, inst->server ? KE_RECEIVE : KE_SEND);
      return 0;

    case KE_SEND:
    LOG(LOGS_INFO,"sending...");
      assert(inst->new_message && message->complete);
      assert(message->length <= sizeof (message->data) && message->length > message->sent);

      // r = gnutls_record_send(inst->tls_session, &message->data[message->sent],
      //                        message->length - message->sent);

      // if (r < 0) {
      //   if (gnutls_error_is_fatal(r)) {
      //     LOG(inst->server ? LOGS_DEBUG : LOGS_ERR,
      //         "Could not send NTS-KE message to %s : %s", inst->label, gnutls_strerror(r));
      //     stop_session(inst);
      //   }
      //   return 0;
      // }

      r = SSL_write(inst->ssl, &message->data[message->sent], message->length - message->sent);

      DEBUG_LOG("Sent %d bytes to %s", r, inst->label);
      LOG(LOGS_INFO,"Sent %d bytes to %s", r, inst->label);
      // hexdump("\e[32;49;1mSenting message:",&message->data[message->sent],message->length - message->sent);
      // printf("\e[39;49;0m");
      message->sent += r;
      if (message->sent < message->length)
        return 0;

      /* Client will receive a response */
      change_state(inst, inst->server ? KE_SHUTDOWN : KE_RECEIVE);
      reset_message(&inst->message);
      inst->new_message = 0;
      return 0;

    case KE_RECEIVE:
      do {
        if (message->length >= sizeof (message->data)) {
          DEBUG_LOG("Message is too long");
          stop_session(inst);
          return 0;
        }

        // r = gnutls_record_recv(inst->tls_session, &message->data[message->length],
        //                        sizeof (message->data) - message->length);

        // if (r < 0) {
        //   /* Handle a renegotiation request on both client and server as
        //      a protocol error */
        //   if (gnutls_error_is_fatal(r) || r == GNUTLS_E_REHANDSHAKE) {
        //     LOG(inst->server ? LOGS_DEBUG : LOGS_ERR,
        //         "Could not receive NTS-KE message from %s : %s",
        //         inst->label, gnutls_strerror(r));
        //     stop_session(inst);
        //   }
        //   return 0;
        // }
        
        r = SSL_read(inst->ssl, &message->data[message->length], sizeof (message->data) - message->length);
        if (r <= 0)
            break;
        message->data[message->sent+r] = '\0';
        LOG(LOGS_INFO,"receive bytes:");

        DEBUG_LOG("Received %d bytes from %s", r, inst->label);
        LOG(LOGS_INFO,"Received %d bytes from %s", r, inst->label);
      // hexdump("\e[32;49;1m Receive message:",&message->data[message->length], sizeof (message->data) - message->length);
      // printf("\e[39;49;0m");
        message->length += r;

      // } while (gnutls_record_check_pending(inst->tls_session) > 0);
      } while(SSL_has_pending(inst->ssl));

      if (!check_message_format(message, r == 0)) {
        LOG(inst->server ? LOGS_DEBUG : LOGS_ERR,
            "Received invalid NTS-KE message from %s", inst->label);
        stop_session(inst);
        return 0;
      }

      /* Wait for more data if the message is not complete yet */
      if (!message->complete)
        return 0;
      
      /* Server will send a response to the client */
      change_state(inst, inst->server ? KE_SEND : KE_SHUTDOWN);

      printf("ke message receive\n");
      /* Return success to process the received message */
      return 1;

    case KE_SHUTDOWN:
    LOG(LOGS_INFO,"shutdown...");
      // r = gnutls_bye(inst->tls_session, GNUTLS_SHUT_RDWR);
      r=SSL_shutdown(inst->ssl);
      do {
        /* We only do unidirectional shutdown */
        r = SSL_shutdown(inst->ssl);
        if (r < 0) {
            switch (SSL_get_error(inst->ssl, r)) {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
            case SSL_ERROR_WANT_ASYNC:
            case SSL_ERROR_WANT_ASYNC_JOB:
                /* We just do busy waiting. Nothing clever */
                continue;
            }
            r = 0;
        }
    } while (r < 0);
      // if (r < 0) {
      // //   if (gnutls_error_is_fatal(r)) {
      //   if(ERR_FATAL_ERROR(r)){
      //     DEBUG_LOG("Shutdown with %s failed : %s", inst->label, gnutls_strerror(r));
      //     stop_session(inst);
      //     return 0;
      //   }

      // //   /* Disable output when the TLS shutdown is trying to receive data */
      // //   set_input_output(inst, gnutls_record_get_direction(inst->tls_session));
      //   return 0;
      // }

      SCK_ShutdownConnection(inst->sock_fd);
      stop_session(inst);

      DEBUG_LOG("Shutdown completed");
      return 0;

    default:
      assert(0);
      return 0;
  }
}

/* ================================================== */

static void
read_write_socket(int fd, int event, void *arg)
{
  NKSN_Instance inst = arg;

  if (!handle_event(inst, event))
    return;

  /* A valid message was received.  Call the handler to process the message,
     and prepare a response if it is a server. */

  reset_message_parsing(&inst->message);

  if (!(inst->handler)(inst->handler_arg)) {
    stop_session(inst);
    return;
  }
}

/* ================================================== */

static time_t
get_time(time_t *t)
{
  struct timespec now;

  LCL_ReadCookedTime(&now, NULL);
  if (t)
    *t = now.tv_sec;

  return now.tv_sec;
}

/* ================================================== */

static void
handle_step(struct timespec *raw, struct timespec *cooked, double dfreq,
            double doffset, LCL_ChangeType change_type, void *anything)
{
  if (change_type != LCL_ChangeUnknownStep && clock_updates < INT_MAX)
    clock_updates++;
}

/* ================================================== */

static int opentls_initialised = 0;

static int
init_opentls(void)
{
  int r;

  if (opentls_initialised)
    return 1;

  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();
  // r = gnutls_global_init();
  // if (r < 0)
  //   LOG_FATAL("Could not initialise %s : %s", "gnutls", gnutls_strerror(r));

  /* Prepare a priority cache for server and client NTS-KE sessions
     (the NTS specification requires TLS1.3 or later) */
  // r = gnutls_priority_init2(&priority_cache,
  //                           "-VERS-SSL3.0:-VERS-TLS1.0:-VERS-TLS1.1:-VERS-TLS1.2:-VERS-DTLS-ALL",
  //                           NULL, GNUTLS_PRIORITY_INIT_DEF_APPEND);
  // if (r < 0) {
  //   LOG(LOGS_ERR, "Could not initialise %s : %s",
  //       "priority cache for TLS", gnutls_strerror(r));
  //   gnutls_global_deinit();    
  // }

  ssl_ctx_s = SSL_CTX_new(TLS_server_method());
  if (ssl_ctx_s == NULL)
    LOG_FATAL("Error creating SSL server context");
  SSL_CTX_enable_sm_tls13_strict(ssl_ctx_s);  
  SSL_CTX_set_alpn_select_cb(ssl_ctx_s,alpn_cb,&alpn_ctx);//1

  ssl_ctx_c = SSL_CTX_new(TLS_client_method());
  if (ssl_ctx_c == NULL)
    LOG_FATAL("Error creating SSL client context");
  
  SSL_CTX_set_next_proto_select_cb(ssl_ctx_c, next_proto_cb, &next_proto);

  if((r=SSL_CTX_set_alpn_protos(ssl_ctx_c, alpn_name,sizeof(alpn_name)))!=0)
  {
    LOG(LOGS_INFO,"set client error!%d",r);
  }
  // if comment, can work remotely and locally; uncomment work only locally?
  if(SSL_CTX_set_ciphersuites(ssl_ctx_c, "TLS_SM4_GCM_SM3")!=1){
    LOG(LOGS_INFO,"\e[32;49;1m set TLS_SM4_GCM_SM3 error!%d\n\e[39;49;0m",r);
    return 0;
  }
  SSL_CTX_set1_curves_list(ssl_ctx_c, "SM2:X25519:prime256v1");
  // SSL_CTX_set1_curves_list(ssl_ctx_c, "prime256v1:X25519:SM2");
  /* Use our clock instead of the system clock in certificate verification */
  // gnutls_global_set_time_function(get_time);

  opentls_initialised = 1;
  DEBUG_LOG("Initialised");

  LCL_AddParameterChangeHandler(handle_step, NULL);

  return 1;
}

/* ================================================== */

static void
deinit_gnutls(void)
{
  // if (!opentls_initialised || credentials_counter > 0)
  //   return;
  if (!opentls_initialised)
    return;
  SSL_CTX_free(ssl_ctx_s);
  SSL_CTX_free(ssl_ctx_c);
  LCL_RemoveParameterChangeHandler(handle_step, NULL);

  // gnutls_priority_deinit(priority_cache);
  // gnutls_global_deinit();
  opentls_initialised = 0;
  DEBUG_LOG("Deinitialised");
}

/* ================================================== */

static void
create_credentials(const char **certs, const char **keys, int n_certs_keys,
                   const char **trusted_certs, uint32_t *trusted_certs_ids,
                   int n_trusted_certs, uint32_t trusted_cert_set)
{
  // gnutls_certificate_credentials_t credentials = NULL;
  int i;

  if (!init_opentls())
    return;

  // r = gnutls_certificate_allocate_credentials(&credentials);
  // if (r < 0)
  //   goto error;
  if (certs && keys) {
    if (trusted_certs || trusted_certs_ids)
      assert(0);

    for (i = 0; i < n_certs_keys; i++) {
      if (!UTI_CheckFilePermissions(keys[i], 0771))
        ;
      // r = gnutls_certificate_set_x509_key_file(credentials, certs[i], keys[i],
      //                                          GNUTLS_X509_FMT_PEM);
      if (SSL_CTX_use_certificate_file(ssl_ctx_s, certs[i], SSL_FILETYPE_PEM) <= 0)
        // LOG_FATAL("Error loading server certificate");
        LOG(LOGS_INFO,"Error loading server certificate");
      if (SSL_CTX_use_PrivateKey_file(ssl_ctx_s, keys[i], SSL_FILETYPE_PEM) <= 0)
        LOG(LOGS_INFO,"Error loading private key");
        // LOG_FATAL("Error loading server private key");
      // if (r < 0)
      //   goto error;
    }
  } else {
    if (certs || keys || n_certs_keys > 0);
      // assert(0);

    // if (trusted_cert_set == 0 && !CNF_GetNoSystemCert()) {
    //   r = gnutls_certificate_set_x509_system_trust(credentials);
    //   if (r < 0)
    //     goto error;
    // }

    // if (trusted_certs && trusted_certs_ids) {
    //   for (i = 0; i < n_trusted_certs; i++) {
    //     struct stat buf;

    //     if (trusted_certs_ids[i] != trusted_cert_set)
    //       continue;

    //     if (stat(trusted_certs[i], &buf) == 0 && S_ISDIR(buf.st_mode))
    //       r = gnutls_certificate_set_x509_trust_dir(credentials, trusted_certs[i],
    //                                                 GNUTLS_X509_FMT_PEM);
    //     else
    //       r = gnutls_certificate_set_x509_trust_file(credentials, trusted_certs[i],
    //                                                  GNUTLS_X509_FMT_PEM);
    //     if (r < 0)
    //       goto error;

    //     DEBUG_LOG("Added %d trusted certs from %s", r, trusted_certs[i]);
    //   }
    // }
  }

  // credentials_counter++;

  // return (NKSN_Credentials)credentials;

// error:
//   LOG(LOGS_ERR, "Could not set credentials : %s", gnutls_strerror(r));
//   if (credentials)
//     gnutls_certificate_free_credentials(credentials);
//   deinit_gnutls();
//   return NULL;
}

/* ================================================== */

// NKSN_Credentials
void
NKSN_CreateServerCertCredentials(const char **certs, const char **keys, int n_certs_keys)
{
  create_credentials(certs, keys, n_certs_keys, NULL, NULL, 0, 0);
}

/* ================================================== */

// NKSN_Credentials
void
NKSN_CreateClientCertCredentials(const char **certs, uint32_t *ids,
                                 int n_certs_ids, uint32_t trusted_cert_set)
{
  create_credentials(NULL, NULL, 0, certs, ids, n_certs_ids, trusted_cert_set);
}

/* ================================================== */

void
NKSN_DestroyCertCredentials()
{
  // gnutls_certificate_free_credentials((gnutls_certificate_credentials_t)credentials);
  credentials_counter--;
  deinit_gnutls();
}

/* ================================================== */

NKSN_Instance
NKSN_CreateInstance(int server_mode, const char *server_name,
                    NKSN_MessageHandler handler, void *handler_arg)
{
  NKSN_Instance inst;

  LOG(LOGS_INFO,"creating server ssl...");
  inst = MallocNew(struct NKSN_Instance_Record);

  inst->server = server_mode;
  inst->server_name = server_name ? Strdup(server_name) : NULL;
  inst->handler = handler;
  inst->handler_arg = handler_arg;
  /* Replace a NULL argument with the session itself */
  if (!inst->handler_arg)
    inst->handler_arg = inst;

  inst->state = KE_STOPPED;
  inst->sock_fd = INVALID_SOCK_FD;
  inst->label = NULL;
  inst->ssl = NULL;
  inst->timeout_id = 0;
  inst->retry_factor = NKE_RETRY_FACTOR2_CONNECT;

  return inst;
}

/* ================================================== */

void
NKSN_DestroyInstance(NKSN_Instance inst)
{
  stop_session(inst);

  Free(inst->server_name);
  Free(inst);
}

/* ================================================== */

int
NKSN_StartSession_s(NKSN_Instance inst, int client_fd, const char *label,
                  double timeout)
{
  assert(inst->state == KE_STOPPED);

  // inst->tls_session = create_tls_session(inst->server, sock_fd, inst->server_name,
  //                                        (gnutls_certificate_credentials_t)credentials,
  //                                        priority_cache);
  inst->ssl = create_tls_session_s(inst->server, client_fd, inst->server_name);
  
  if (!inst->ssl)
    return 0;
  
 
  inst->sock_fd = client_fd;
  SCH_AddFileHandler(client_fd, SCH_FILE_INPUT, read_write_socket, inst);

  inst->label = Strdup(label);
  inst->timeout_id = SCH_AddTimeoutByDelay(timeout, session_timeout, inst);
  inst->retry_factor = NKE_RETRY_FACTOR2_CONNECT;

  reset_message(&inst->message);
  inst->new_message = 0;

  change_state(inst, inst->server ? KE_HANDSHAKE : KE_WAIT_CONNECT);

  return 1;
}

int
NKSN_StartSession_c(NKSN_Instance inst, int sock_fd, const char *label,
                  double timeout)
{
  assert(inst->state == KE_STOPPED);

  // inst->tls_session = create_tls_session(inst->server, sock_fd, inst->server_name,
  //                                        (gnutls_certificate_credentials_t)credentials,
  //                                        priority_cache);
  inst->ssl = create_tls_session_c(inst->server, sock_fd, inst->server_name);


  if (!inst->ssl)
    return 0;

  inst->sock_fd = sock_fd;
  SCH_AddFileHandler(sock_fd, SCH_FILE_INPUT, read_write_socket, inst);

  inst->label = Strdup(label);
  inst->timeout_id = SCH_AddTimeoutByDelay(timeout, session_timeout, inst);
  inst->retry_factor = NKE_RETRY_FACTOR2_CONNECT;

  reset_message(&inst->message);
  inst->new_message = 0;

  change_state(inst, inst->server ? KE_HANDSHAKE : KE_WAIT_CONNECT);

  return 1;
}

/* ================================================== */

void
NKSN_BeginMessage(NKSN_Instance inst)
{
  reset_message(&inst->message);
  inst->new_message = 1;
}

/* ================================================== */

int
NKSN_AddRecord(NKSN_Instance inst, int critical, int type, const void *body, int body_length)
{
  assert(inst->new_message && !inst->message.complete);
  assert(type != NKE_RECORD_END_OF_MESSAGE);

  return add_record(&inst->message, critical, type, body, body_length);
}

/* ================================================== */

int
NKSN_EndMessage(NKSN_Instance inst)
{
  assert(!inst->message.complete);

  /* Terminate the message */
  if (!add_record(&inst->message, 1, NKE_RECORD_END_OF_MESSAGE, NULL, 0))
    return 0;

  inst->message.complete = 1;

  return 1;
}

/* ================================================== */

int
NKSN_GetRecord(NKSN_Instance inst, int *critical, int *type, int *body_length,
               void *body, int buffer_length)
{
  int type2;

  assert(inst->message.complete);

  if (body_length)
    *body_length = 0;

  if (!get_record(&inst->message, critical, &type2, body_length, body, buffer_length))
    return 0;

  /* Hide the end-of-message record */
  if (type2 == NKE_RECORD_END_OF_MESSAGE)
    return 0;

  if (type)
    *type = type2;

  return 1;
}

/* ================================================== */

int
NKSN_GetKeys(NKSN_Instance inst, SIV_Algorithm siv, NKE_Key *c2s, NKE_Key *s2c)
{
  int length = SIV_GetKeyLength(siv);

  if (length <= 0 || length > sizeof (c2s->key) || length > sizeof (s2c->key)) {
    DEBUG_LOG("Invalid algorithm");
    return 0;
  }
  
  // memset(inst->ssl,inst->ssl->exporter_master_secret);
  // if (gnutls_prf_rfc5705(inst->tls_session,
  if (SSL_export_keying_material(inst->ssl,(char *)c2s->key,length,
                         NKE_EXPORTER_LABEL,sizeof (NKE_EXPORTER_LABEL) - 1, 
                         NKE_EXPORTER_CONTEXT_C2S, 
                         sizeof (NKE_EXPORTER_CONTEXT_C2S) - 1,1)
                        // NKE_EXPORTER_CONTEXT_C2S, 
                        //  0,1)
                          != 1 ||
      // gnutls_prf_rfc5705(inst->tls_session,
      SSL_export_keying_material(inst->ssl,(char *)s2c->key,length,
                         NKE_EXPORTER_LABEL,sizeof (NKE_EXPORTER_LABEL) - 1, 
                         NKE_EXPORTER_CONTEXT_S2C, 
                         sizeof (NKE_EXPORTER_CONTEXT_S2C) - 1,1)
                        // NKE_EXPORTER_CONTEXT_S2C, 
                        //  0,1)
                          != 1) {
    DEBUG_LOG("\e[31;49;1m Could not export key\e[39;49;0m");
    LOG(LOGS_INFO,"\e[31;49;1m Could not export key\e[39;49;0m");
    return 0;
  }

  // memset(c2s->key,2,length);
  // memset(s2c->key,2,length);
  hexdump("c2s=",(void*)c2s->key,length);
  hexdump("s2c=",(void*)s2c->key,length);
  c2s->length = length;
  s2c->length = length;

  return 1;
}

/* ================================================== */

int
NKSN_IsStopped(NKSN_Instance inst)
{
  return inst->state == KE_STOPPED;
}

/* ================================================== */

void
NKSN_StopSession(NKSN_Instance inst)
{
  stop_session(inst);
}

/* ================================================== */

int
NKSN_GetRetryFactor(NKSN_Instance inst)
{
  return inst->retry_factor;
}
