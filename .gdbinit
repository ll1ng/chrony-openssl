set args -F -1 -f ./chronys.conf -d
#set args -F -1 -x -f ./chronyc.conf -d
#set args -F -1 -f ./chronys.conf -d
set follow-fork-mode child
#set follow-fork-mode parent
#b SSL_do_handshake
add-symbol-file /home/ling/temp/Tongsuo-8.4.0/libcrypto.so.3
add-symbol-file /home/ling/temp/Tongsuo-8.4.0/libssl.so.3
#b /home/ling/temp/Tongsuo-8.4.0/ssl/statem/statem.c:908
#b /home/ling/temp/Tongsuo-8.4.0/ssl/record/rec_layer_s3.c:1195
#b SSL_do_handshake
#b add_key_share
#b tls_construct_ctos_key_share
#b /mnt/d/chrony-4.5/nts_ke_session.c:970
b /mnt/d/chrony-4.5/nts_ke_session.c:1254
#b /home/ling/temp/Tongsuo-8.4.0/ssl/statem/statem.c:363
#b /home/ling/temp/Tongsuo-8.4.0/ssl/statem/statem.c:471
#b tls_get_message_header
#b /home/ling/temp/Tongsuo-8.4.0/ssl/statem/statem_lib.c:1261
#b /home/ling/temp/Tongsuo-8.4.0/ssl/record/rec_layer_s3.c:298
#b SSL_CTX_set_alpn_protos
#b /home/ling/temp/Tongsuo-8.4.0/ssl/ssl_lib.c:3175
#b SSL_select_next_proto
#b /mnt/d/chrony-4.5/nts_ke_client.c:189
#b /mnt/d/chrony-4.5/nts_ntp_client.c:504
#b /mnt/d/chrony-4.5/nts_ntp_auth.c:180
#b SSL_CTX_set_alpn_select_cb
#b SSL_CTX_set_next_proto_select_cb
#b next_proto_cb
#b SSL_CTX_set_ciphersuites
#b alpn_cb
#b deinit_gnutls
#b MAI_CleanupAndExit
#b LCL_Initialise
#b LCL_AddParameterChangeHandler
#b LCL_RemoveParameterChangeHandler
#b LCL_AccumulateFrequencyAndOffsetNoHandlers
#b LCL_AccumulateFrequencyAndOffsetNoHandlers
#b LCL_Finalise
#disable 2 3
r
#sleep 5
#set follow-fork-mode child
#signal SIGINT
#b BIO_write
#b /home/ling/temp/Tongsuo-8.4.0/crypto/bio/bio_lib.c:362
#c
#c
#b bio_write_intern
#c
