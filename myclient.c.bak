#include <stdio.h>

#include "open62541.h"

/* PEM 파일 로드 함수 */
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
main(void) {
    UA_Client *client = UA_Client_new();
    UA_ClientConfig *config = UA_Client_getConfig(client);

    // 인증서 및 키 파일 로드
    UA_ByteString certificate = UA_BYTESTRING_NULL;
    UA_ByteString privateKey = UA_BYTESTRING_NULL;

    if(loadFile("client_cert.der", &certificate) != UA_STATUSCODE_GOOD) {
        printf("클라이언트 인증서 로드 실패\n");
        return -1;
    }
    if(loadFile("client_key.der", &privateKey) != UA_STATUSCODE_GOOD) {
        printf("클라이언트 키 로드 실패\n");
        UA_ByteString_clear(&certificate);
        return -1;
    }

    // 클라이언트 암호화 설정
    UA_ByteString trustList[1];  // 신뢰 목록을 위해
    trustList[0] = certificate;

    UA_StatusCode retval = UA_ClientConfig_setDefaultEncryption(
        config, certificate, privateKey, trustList, 1, NULL, 0);

    if(retval != UA_STATUSCODE_GOOD) {
        printf("클라이언트 암호화 설정 실패\n");
        UA_ByteString_clear(&certificate);
        UA_ByteString_clear(&privateKey);
        return -1;
    }

    // 서버 연결
    retval = UA_Client_connect(client, "opc.tcp://BOOK-13MRNGG60C:4840");
    if(retval != UA_STATUSCODE_GOOD) {
        printf("서버 연결 실패: %s\n", UA_StatusCode_name(retval));
        UA_Client_delete(client);
        return (int)retval;
    }

    // 노드 값 읽기
    UA_Variant value;
    UA_Variant_init(&value);
    const UA_NodeId nodeId =
        UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER_SERVERSTATUS_CURRENTTIME);
    retval = UA_Client_readValueAttribute(client, nodeId, &value);

    if(retval == UA_STATUSCODE_GOOD &&
       UA_Variant_hasScalarType(&value, &UA_TYPES[UA_TYPES_DATETIME])) {
        UA_DateTime raw_date = *(UA_DateTime *)value.data;
        UA_DateTimeStruct dts = UA_DateTime_toStruct(raw_date);
        printf("현재 날짜: %02u-%02u-%04u %02u:%02u:%02u.%03u\n", dts.day, dts.month,
               dts.year, dts.hour, dts.min, dts.sec, dts.milliSec);
    } else {
        printf("노드 값 읽기 실패: %s\n", UA_StatusCode_name(retval));
    }

    UA_Variant_clear(&value);
    UA_Client_delete(client);
    UA_ByteString_clear(&certificate);
    UA_ByteString_clear(&privateKey);

    return 0;
}
