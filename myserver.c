#include <signal.h>
#include <stdio.h>

#include "open62541.h"

UA_Boolean running = true;

/* 종료 신호 처리기 */
static void
stopHandler(int sign) {
    running = false;
}

/* 인증서 및 개인 키 로드 함수 */
UA_StatusCode
loadFile(const char *path, UA_ByteString *bs) {
    FILE *fp = fopen(path, "rb");
    if(!fp) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    fseek(fp, 0, SEEK_END);
    long fileSize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    UA_ByteString_allocBuffer(bs, fileSize);
    fread(bs->data, sizeof(UA_Byte), fileSize, fp);
    fclose(fp);
    return UA_STATUSCODE_GOOD;
}

int
main(int argc, char **argv) {
    signal(SIGINT, stopHandler);
    signal(SIGTERM, stopHandler);

    /* 서버 생성 */
    UA_Server *server = UA_Server_new();
    UA_ServerConfig *config = UA_Server_getConfig(server);

    /* 인증서 및 개인 키 로드 */
    UA_ByteString certificate = UA_BYTESTRING_NULL;
    UA_ByteString privateKey = UA_BYTESTRING_NULL;

    UA_StatusCode retval = loadFile("server_cert.der", &certificate);
    if(retval != UA_STATUSCODE_GOOD) {
        printf("Error loading certificate\n");
        return (int)retval;
    }

    retval = loadFile("server_key.pem", &privateKey);
    if(retval != UA_STATUSCODE_GOOD) {
        printf("Error loading private key\n");
        UA_ByteString_clear(&certificate);
        return (int)retval;
    }

    /* 기본 설정 초기화 (보안 정책 제외) */
    retval = UA_ServerConfig_setMinimal(config, 4840, NULL);
    if(retval != UA_STATUSCODE_GOOD) {
        printf("Error setting minimal config\n");
        UA_ByteString_clear(&certificate);
        UA_ByteString_clear(&privateKey);
        return (int)retval;
    }

    /* Basic256Sha256 보안 정책만 추가 */
    retval = UA_ServerConfig_addSecurityPolicyBasic256Sha256(config, &certificate,
                                                             &privateKey);
    if(retval != UA_STATUSCODE_GOOD) {
        printf("Error adding security policy Basic256Sha256\n");
        UA_ByteString_clear(&certificate);
        UA_ByteString_clear(&privateKey);
        return (int)retval;
    }

    /* 엔드포인트 추가 (보안 정책 및 메시지 보안 모드) */
    UA_String endpointUrl = UA_STRING("opc.tcp://localhost:4840");
    retval = UA_ServerConfig_addEndpoint(
        config, UA_STRING("http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256"),
        UA_MESSAGESECURITYMODE_SIGNANDENCRYPT);
    if(retval != UA_STATUSCODE_GOOD) {
        printf("Error adding endpoint\n");
        UA_ByteString_clear(&certificate);
        UA_ByteString_clear(&privateKey);
        return (int)retval;
    }

    /* ApplicationURI 직접 설정 */
    UA_String applicationUri = UA_STRING("urn:my_custom_application_uri");
    UA_String_copy(&applicationUri, &config->applicationDescription.applicationUri);

    /* 서버 시작 */
    retval = UA_Server_run_startup(server);
    if(retval != UA_STATUSCODE_GOOD) {
        printf("Server startup failed\n");
        return (int)retval;
    }

    while(running) {
        UA_Server_run_iterate(server, true);
    }

    /* 서버 종료 */
    UA_Server_run_shutdown(server);
    UA_ByteString_clear(&certificate);
    UA_ByteString_clear(&privateKey);
    UA_Server_delete(server);

    return 0;
}
