

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>


#include <unistd.h>


#include <libwandder.h>
#include <libwandder_etsili.h>


#define ENC_USEQUENCE(enc) wandder_encode_next(enc, WANDDER_TAG_SEQUENCE, \
        WANDDER_CLASS_UNIVERSAL_CONSTRUCT, WANDDER_TAG_SEQUENCE, NULL, 0)

#define ENC_CSEQUENCE(enc, x) wandder_encode_next(enc, WANDDER_TAG_SEQUENCE, \
        WANDDER_CLASS_CONTEXT_CONSTRUCT, x, NULL, 0)

#define END_ENCODED_SEQUENCE(enc, x) \
        wandder_encode_endseq_repeat(enc, x);

#define MEMCPYPREENCODE(ptr, itembuf) {memcpy(ptr, itembuf->buf, itembuf->len); ptr+=itembuf->len;}

#define ENDCONSTRUCTEDBLOCK(ptr,num) {for (int uniuqevari = 0; uniuqevari < num*2; uniuqevari++){*ptr = 0;ptr+=1;}}

#define PRINTBUF(ptr,len) for (int uniuqevari = 0; uniuqevari< len; uniuqevari++)\
            printf("%02x ",*(uint8_t *)(ptr+uniuqevari));\
        printf("\n");

#define TIMEFUNC(func, reset, num) {                                                        \
    struct timespec start, end;                                                             \
    uint64_t delta_us = 0;                                                                  \
    uint64_t samples = 0;                                                                   \
    uint64_t total = 0;                                                                     \
    for (int uniuqevari = 0; uniuqevari < num; uniuqevari++){                               \
        clock_gettime(CLOCK_MONOTONIC_RAW, &start);                                         \
        func                                                                                \
        clock_gettime(CLOCK_MONOTONIC_RAW, &end);                                           \
        reset                                                                               \
        delta_us = (end.tv_sec - start.tv_sec) * 1000000000 + (end.tv_nsec - start.tv_nsec);\
        total += delta_us;                                                                  \
        samples++;                                                                          \
        if (total > (UINT32_MAX)){                                                          \
            total = total/samples;                                                          \
            samples = 1;                                                                    \
        }                                                                                   \
    }                                                                                       \
    printf("took avg:%6luns over %d samples\n",total/samples , num);}

uint8_t etsi_ipccoid[4] = {0x05, 0x03, 0x0a, 0x02};
uint8_t etsi_ipirioid[4] = {0x05, 0x03, 0x0a, 0x01};
uint8_t etsi_ipmmccoid[4] = {0x05, 0x05, 0x06, 0x02};
uint8_t etsi_ipmmirioid[4] = {0x05, 0x05, 0x06, 0x01};
uint8_t trueResult[] = {
            0xa1, 0x80, 
                0x80, 0x08, 0x04, 0x00, 0x02, 0x02, 0x05, 0x01, 0x11, 0x00,
                0x81, 0x04, 0x6c, 0x69, 0x69, 0x64, 
                0x82, 0x06, 0x61, 0x75, 0x74, 0x68, 0x63, 0x63, 
                0xa3, 0x80, 
                    0xa0, 0x80, 
                        0x80, 0x0a, 0x6f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x6f, 0x72, 0x69, 0x64,
                        0x81, 0x0d, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x65, 0x6c, 0x65, 0x6d, 0x69, 0x64, 
                    0x00, 0x00, 
                    0x81, 0x83, 0x00, 0x00, 0x04, 0xfe, 0xed, 0xbe, 0xef, 
                    0x82, 0x07, 0x64, 0x65, 0x6c, 0x69, 0x76, 0x63, 0x63, 
                0x00, 0x00, 
                0x84, 0x85, 0x00, 0x00, 0x00, 0x00, 0x02, 0xde, 0xad,
                0x86, 0x0a, 0x69, 0x6e, 0x74, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x69, 0x64,
                0xa7, 0x80,
                    0x80, 0x83, 0x00, 0x00, 0x04, 0x0b, 0xad, 0xca, 0xfe, 
                    0x81, 0x85, 0x00, 0x00, 0x00, 0x00, 0x02, 0x13, 0x37, 
                0x00, 0x00,
                0x88, 0x86, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01,
            0x00, 0x00};
/*
[1] (8 elem)
    [0] (8 byte) 04 00 02 02 05 01 11 00
    [1] liid
    [2] authcc
    [3] (3 elem)
        [0] (2 elem)
            [0] operatorid
            [1] networkelemid
        [1] (4 byte) FEEDBEEF
        [2] delivcc
    [4] (2 byte) DEAD
    [6] intpointid
    [7] (2 elem)
        [0] (4 byte) 0BADCAFE
        [1] (2 byte) 1337
    [8] (1 byte) 01
  */

uint8_t ipcc_truth[] = {
        0xa2, 0x3c, 
            0xa1, 0x3a, 
                0x30, 0x38, 
                    0x80, 0x01, 0x42, 
                    0xa2, 0x33, 
                        0xa2, 0x31, 
                            0x80, 0x04, 0x05, 0x03, 0x0a, 0x02, 
                            0xa1, 0x29, 
                                0x80, 0x27, 
                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};


typedef struct wandder_pshdr {
    uint32_t totallen;
    wandder_buf_t block_0;
    wandder_buf_t cin;
    wandder_buf_t block_1;
    wandder_buf_t seqno;
    wandder_buf_t block_2;
    wandder_buf_t sec;
    wandder_buf_t usec;
    wandder_buf_t block_3;
} wandder_pshdr_t;

void wandder_pshdr_update(int64_t cin,
        int64_t seqno, struct timeval *tv, wandder_pshdr_t * hdr) {

    ber_rebuild_integer(
        WANDDER_CLASS_CONTEXT_PRIMITIVE, 
        1, 
        &(cin), 
        sizeof(int64_t),
        hdr->cin.buf);

    ber_rebuild_integer(
        WANDDER_CLASS_CONTEXT_PRIMITIVE, 
        4, 
        &(seqno), 
        sizeof(int64_t),
        hdr->seqno.buf);

    ber_rebuild_integer(
        WANDDER_CLASS_CONTEXT_PRIMITIVE, 
        0, 
        &(tv->tv_sec), 
        sizeof(tv->tv_sec),
        hdr->sec.buf);

    ber_rebuild_integer(
        WANDDER_CLASS_CONTEXT_PRIMITIVE, 
        1, 
        &(tv->tv_usec), 
        sizeof(tv->tv_usec),
        hdr->usec.buf);
}


typedef enum {
    OPENLI_PREENCODE_USEQUENCE,
    OPENLI_PREENCODE_CSEQUENCE_0,
    OPENLI_PREENCODE_CSEQUENCE_1,
    OPENLI_PREENCODE_CSEQUENCE_2,
    OPENLI_PREENCODE_CSEQUENCE_3,
    OPENLI_PREENCODE_CSEQUENCE_7,	/* Microsecond timestamp */
    OPENLI_PREENCODE_CSEQUENCE_11,  /* IPMMIRI */
    OPENLI_PREENCODE_CSEQUENCE_12,  /* IPMMCC */
    OPENLI_PREENCODE_PSDOMAINID,
    OPENLI_PREENCODE_LIID,
    OPENLI_PREENCODE_AUTHCC,
    OPENLI_PREENCODE_OPERATORID,
    OPENLI_PREENCODE_NETWORKELEMID,
    OPENLI_PREENCODE_DELIVCC,
    OPENLI_PREENCODE_INTPOINTID,
    OPENLI_PREENCODE_TVCLASS,
    OPENLI_PREENCODE_IPMMIRIOID,
    OPENLI_PREENCODE_IPCCOID,
    OPENLI_PREENCODE_IPIRIOID,
    OPENLI_PREENCODE_IPMMCCOID,
    OPENLI_PREENCODE_DIRFROM,
    OPENLI_PREENCODE_DIRTO,
    OPENLI_PREENCODE_DIRUNKNOWN,
    OPENLI_PREENCODE_INTEGERSPACE,
    OPENLI_PREENCODE_LAST

} preencode_index_t;

typedef struct etsili_intercept_details {
    char *liid;
    char *authcc;
    char *delivcc;
    char *intpointid;
    char *operatorid;
    char *networkelemid;
} etsili_intercept_details_t;


static inline wandder_pshdr_t * init_pshdr_pc_ber(wandder_buf_t **precomputed, int64_t cin,
        int64_t seqno, struct timeval *tv) {

    /* hdrdata should be pretty static for each ETSI LI record, so
     * you can populate it once and repeatedly use it.
     * CIN, seqno and tv will change for each record, so I've made them
     * into separate parameters.
     */
    wandder_pshdr_t *header = malloc(sizeof(wandder_pshdr_t));

    uint32_t totallen = 
        precomputed[OPENLI_PREENCODE_CSEQUENCE_1]->len+
        precomputed[OPENLI_PREENCODE_PSDOMAINID]->len+
        precomputed[OPENLI_PREENCODE_LIID]->len+
        precomputed[OPENLI_PREENCODE_AUTHCC]->len+
        precomputed[OPENLI_PREENCODE_CSEQUENCE_3]->len+
        precomputed[OPENLI_PREENCODE_CSEQUENCE_0]->len+
        precomputed[OPENLI_PREENCODE_OPERATORID]->len+
        precomputed[OPENLI_PREENCODE_NETWORKELEMID]->len+
        2 + //endseq
        9 + //precomputed[]->len+//cin integer size
        precomputed[OPENLI_PREENCODE_DELIVCC]->len+
        2 + //endseq
        9 +//precomputed[]->len+//seqno integer size
        (
            (precomputed[OPENLI_PREENCODE_INTPOINTID]) ? 
                (
                    precomputed[OPENLI_PREENCODE_INTPOINTID]->len +
                    precomputed[OPENLI_PREENCODE_CSEQUENCE_7]->len
                ): 
                (
                    precomputed[OPENLI_PREENCODE_CSEQUENCE_7]->len
                ) 
        )+ 
        9 + //precomputed[]->len+//sec integer size
        9 + //precomputed[]->len+//usec integer size
        2 +
        precomputed[OPENLI_PREENCODE_TVCLASS]->len+
        2;


    uint8_t *ptr = malloc(totallen);
    header->totallen = totallen;


    //////////////////////////////////////////////////////////////// block 0
    header->block_0.buf = ptr;
    MEMCPYPREENCODE(ptr, precomputed[OPENLI_PREENCODE_CSEQUENCE_1]);
    MEMCPYPREENCODE(ptr, precomputed[OPENLI_PREENCODE_PSDOMAINID]);
    MEMCPYPREENCODE(ptr, precomputed[OPENLI_PREENCODE_LIID]);
    MEMCPYPREENCODE(ptr, precomputed[OPENLI_PREENCODE_AUTHCC]);
    MEMCPYPREENCODE(ptr, precomputed[OPENLI_PREENCODE_CSEQUENCE_3]);
    MEMCPYPREENCODE(ptr, precomputed[OPENLI_PREENCODE_CSEQUENCE_0]);
    MEMCPYPREENCODE(ptr, precomputed[OPENLI_PREENCODE_OPERATORID]);
    MEMCPYPREENCODE(ptr, precomputed[OPENLI_PREENCODE_NETWORKELEMID]);
    ENDCONSTRUCTEDBLOCK(ptr,1) //endseq
    header->block_0.len = ((void *)ptr) - header->block_0.buf;
    //////////////////////////////////////////////////////////////// cin
    header->cin.buf = ptr;
    ptr += ber_rebuild_integer(
        WANDDER_CLASS_CONTEXT_PRIMITIVE, 
        1, 
        &(cin), 
        sizeof(int64_t),
        header->cin.buf);
    header->cin.len = ((void *)ptr) - header->cin.buf;
    //////////////////////////////////////////////////////////////// block 1
    header->block_1.buf = ptr;
    MEMCPYPREENCODE(ptr, precomputed[OPENLI_PREENCODE_DELIVCC]);
    ENDCONSTRUCTEDBLOCK(ptr,1);//endseq
    header->block_1.len = ((void *)ptr) - header->block_1.buf;
    //////////////////////////////////////////////////////////////// seqno
    header->seqno.buf = ptr;
    ptr+= ber_rebuild_integer(
        WANDDER_CLASS_CONTEXT_PRIMITIVE, 
        4, 
        &(seqno), 
        sizeof(int64_t),
        header->seqno.buf);
    header->seqno.len = ((void *)ptr) - header->seqno.buf;
    //////////////////////////////////////////////////////////////// block 2
    header->block_2.buf = ptr;
    if (precomputed[OPENLI_PREENCODE_INTPOINTID]){
        MEMCPYPREENCODE(ptr, precomputed[OPENLI_PREENCODE_INTPOINTID]);
    }
    MEMCPYPREENCODE(ptr, precomputed[OPENLI_PREENCODE_CSEQUENCE_7]);
    header->block_2.len = ((void *)ptr) - header->block_2.buf;
    //////////////////////////////////////////////////////////////// sec
    header->sec.buf = ptr;
    ptr+= ber_rebuild_integer(
        WANDDER_CLASS_CONTEXT_PRIMITIVE, 
        0, 
        &(tv->tv_sec), 
        sizeof(tv->tv_sec),
        header->sec.buf);
    header->sec.len = ((void *)ptr) - header->sec.buf;
    //////////////////////////////////////////////////////////////// usec
    header->usec.buf = ptr;
    ptr+= ber_rebuild_integer(
        WANDDER_CLASS_CONTEXT_PRIMITIVE, 
        1, 
        &(tv->tv_usec), 
        sizeof(tv->tv_usec),
        header->usec.buf);
    header->usec.len = ((void *)ptr) - header->usec.buf;
    //////////////////////////////////////////////////////////////// block 3
    header->block_3.buf = ptr;
    ENDCONSTRUCTEDBLOCK(ptr,1);//endseq
    MEMCPYPREENCODE(ptr, precomputed[OPENLI_PREENCODE_TVCLASS]);
    ENDCONSTRUCTEDBLOCK(ptr,1);//endseq
    header->block_3.len = ((void *)ptr) - header->block_3.buf;

    return header;
}

static inline void encode_ipcc_body(wandder_encoder_t *encoder,
        wandder_encode_job_t *precomputed, void *ipcontent, uint32_t iplen,
        uint8_t dir) {

    uint32_t dir32 = dir;
    wandber_encoded_result_t *res_ber;  
    wandber_encoder_t *enc_ber = init_wandber_encoder();
    wandder_encode_job_t *jobarray[8];

    jobarray[0] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_2]);
    jobarray[1] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_1]);
    jobarray[2] = &(precomputed[OPENLI_PREENCODE_USEQUENCE]);


    wandder_encode_next_preencoded(encoder, jobarray, 3);

    wandber_encode_next_preencoded(enc_ber, jobarray, 3);
    res_ber = wandber_encode_finish(enc_ber); 
    //save output from res_ber
    free(res_ber->buf);
    free(res_ber);
    res_ber = NULL;



    if (dir == 0) {
        jobarray[3] = &(precomputed[OPENLI_PREENCODE_DIRFROM]);
        wandder_encode_next_preencoded(encoder, jobarray, 1);
    } else if (dir == 1) {
        jobarray[3] = &(precomputed[OPENLI_PREENCODE_DIRTO]);
        wandder_encode_next_preencoded(encoder, jobarray, 1);
    } else if (dir == 2) {
        jobarray[3] = &(precomputed[OPENLI_PREENCODE_DIRUNKNOWN]);
        wandder_encode_next_preencoded(encoder, jobarray, 1);
    } else {
        wandder_encode_next(encoder, WANDDER_TAG_ENUM,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 0, &dir32,
                sizeof(uint32_t));
    }
    res_ber = wandber_encode_finish(enc_ber); 
    //save output from res_ber
    free(res_ber->buf);
    free(res_ber);
    res_ber = NULL;

    jobarray[0] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_2]);
    jobarray[1] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_2]);
    jobarray[2] = &(precomputed[OPENLI_PREENCODE_IPCCOID]);
    jobarray[3] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_1]);

    wandder_encode_next_preencoded(encoder, jobarray, 4);

    wandder_encode_next(encoder, WANDDER_TAG_IPPACKET,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 0, ipcontent, iplen);

    END_ENCODED_SEQUENCE(encoder, 7);

    free_wandber_encoder(enc_ber);

}

void etsili_preencode_static_fields_ber(
        wandder_buf_t **pendarray, etsili_intercept_details_t *details) {

    wandder_buf_t *p;
    int tvclass = 1;
    uint32_t dirin = 0, dirout = 1, dirunk = 2;

    memset(pendarray, 0, sizeof(p) * OPENLI_PREENCODE_LAST);

    pendarray[OPENLI_PREENCODE_USEQUENCE] = build_ber_field(
            WANDDER_CLASS_UNIVERSAL_CONSTRUCT, 
            WANDDER_TAG_SEQUENCE,
            WANDDER_TAG_SEQUENCE,
            NULL, 
            0,
            NULL,
            0);

    pendarray[OPENLI_PREENCODE_CSEQUENCE_0] =  build_ber_field(
            WANDDER_CLASS_CONTEXT_CONSTRUCT, 
            0,
            WANDDER_TAG_SEQUENCE,
            NULL, 
            0,
            NULL,
            0);

    pendarray[OPENLI_PREENCODE_CSEQUENCE_1] =  build_ber_field(
            WANDDER_CLASS_CONTEXT_CONSTRUCT, 
            1,
            WANDDER_TAG_SEQUENCE,
            NULL, 
            0,
            NULL,
            0);

    pendarray[OPENLI_PREENCODE_CSEQUENCE_2] =  build_ber_field(
            WANDDER_CLASS_CONTEXT_CONSTRUCT, 
            2,
            WANDDER_TAG_SEQUENCE,
            NULL, 
            0,
            NULL,
            0);

    pendarray[OPENLI_PREENCODE_CSEQUENCE_3] =  build_ber_field(
            WANDDER_CLASS_CONTEXT_CONSTRUCT, 
            3,
            WANDDER_TAG_SEQUENCE,
            NULL, 
            0,
            NULL,
            0);

    pendarray[OPENLI_PREENCODE_CSEQUENCE_7] =  build_ber_field(
            WANDDER_CLASS_CONTEXT_CONSTRUCT, 
            7,
            WANDDER_TAG_SEQUENCE,
            NULL, 
            0,
            NULL,
            0);

    pendarray[OPENLI_PREENCODE_CSEQUENCE_11] =  build_ber_field(
            WANDDER_CLASS_CONTEXT_CONSTRUCT, 
            11,
            WANDDER_TAG_SEQUENCE,
            NULL, 
            0,
            NULL,
            0);

    pendarray[OPENLI_PREENCODE_CSEQUENCE_12] =  build_ber_field(
            WANDDER_CLASS_CONTEXT_CONSTRUCT, 
            12,
            WANDDER_TAG_SEQUENCE,
            NULL, 
            0,
            NULL,
            0);

    //TODO i dont think this is 100% correct but i cant see anything wrong
    pendarray[OPENLI_PREENCODE_PSDOMAINID] =  build_ber_field( 
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            0,
            WANDDER_TAG_OID,
            (uint8_t *)WANDDER_ETSILI_PSDOMAINID, 
            sizeof WANDDER_ETSILI_PSDOMAINID,
            NULL,
            0);

    pendarray[OPENLI_PREENCODE_LIID] =  build_ber_field( 
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            1,
            WANDDER_TAG_OCTETSTRING,
            (uint8_t *)details->liid, 
            strlen(details->liid),
            NULL,
            0);

    pendarray[OPENLI_PREENCODE_AUTHCC] =  build_ber_field( 
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            2,
            WANDDER_TAG_OCTETSTRING,
            (uint8_t *)details->authcc, 
            strlen(details->authcc),
            NULL,
            0);

    pendarray[OPENLI_PREENCODE_OPERATORID] =  build_ber_field( 
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            0,
            WANDDER_TAG_OCTETSTRING,
            (uint8_t *)details->operatorid, 
            strlen(details->operatorid),
            NULL,
            0);

    pendarray[OPENLI_PREENCODE_NETWORKELEMID] =  build_ber_field( 
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            1,
            WANDDER_TAG_OCTETSTRING,
            (uint8_t *)details->networkelemid, 
            strlen(details->networkelemid),
            NULL,
            0);

    pendarray[OPENLI_PREENCODE_DELIVCC] =  build_ber_field( 
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            2,
            WANDDER_TAG_OCTETSTRING,
            (uint8_t *)details->delivcc, 
            strlen(details->delivcc),
            NULL,
            0);

    //either build the field or set it NULL
    pendarray[OPENLI_PREENCODE_INTPOINTID] =  (details->intpointid) ? build_ber_field( 
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            6,
            WANDDER_TAG_OCTETSTRING,
            (uint8_t *)details->intpointid, 
            strlen(details->intpointid),
            NULL,
            0) : NULL;

    pendarray[OPENLI_PREENCODE_TVCLASS] =  build_ber_field( 
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            8,
            WANDDER_TAG_ENUM,
            (uint8_t *)(&tvclass), 
            sizeof tvclass,
            NULL,
            0);

    pendarray[OPENLI_PREENCODE_IPMMIRIOID] =  build_ber_field( 
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            0,
            WANDDER_TAG_RELATIVEOID,
            etsi_ipmmirioid, 
            sizeof etsi_ipmmirioid,
            NULL,
            0);

    pendarray[OPENLI_PREENCODE_IPCCOID] =  build_ber_field( 
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            0,
            WANDDER_TAG_RELATIVEOID,
            etsi_ipccoid, 
            sizeof etsi_ipccoid,
            NULL,
            0);

    pendarray[OPENLI_PREENCODE_IPIRIOID] =  build_ber_field( 
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            0,
            WANDDER_TAG_RELATIVEOID,
            etsi_ipirioid, 
            sizeof etsi_ipirioid,
            NULL,
            0);

    pendarray[OPENLI_PREENCODE_IPMMCCOID] =  build_ber_field( 
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            0,
            WANDDER_TAG_RELATIVEOID,
            etsi_ipmmccoid, 
            sizeof etsi_ipmmccoid,
            NULL,
            0);

    pendarray[OPENLI_PREENCODE_DIRFROM] =  build_ber_field( 
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            0,
            WANDDER_TAG_ENUM,
            (uint8_t *)(&dirin), 
            sizeof dirin,
            NULL,
            0);

    pendarray[OPENLI_PREENCODE_DIRTO] =  build_ber_field( 
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            0,
            WANDDER_TAG_ENUM,
            (uint8_t *)(&dirout), 
            sizeof dirout,
            NULL,
            0);

    pendarray[OPENLI_PREENCODE_DIRUNKNOWN] =  build_ber_field( 
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            0,
            WANDDER_TAG_ENUM,
            (uint8_t *)(&dirunk), 
            sizeof dirunk,
            NULL,
            0);

}

void etsili_clear_preencoded_fields_ber( wandder_buf_t **pendarray ) {

    preencode_index_t i;

    for (i = 0; i < OPENLI_PREENCODE_LAST; i++) {
        if (pendarray[i]) {
            free(pendarray[i]->buf);
            free(pendarray[i]);
        }
    }
}

wandber_encoded_result_t *encode_etsi_ipcc(
        wandder_buf_t **precomputed, int64_t cin, int64_t seqno,
        struct timeval *tv, void *ipcontents, uint32_t iplen, uint8_t dir,
        wandder_pshdr_t **hdr) {

    if (*hdr){
        wandder_pshdr_update(cin, seqno, tv, *hdr);
    } else {
        *hdr = init_pshdr_pc_ber(precomputed, cin, seqno, tv);
    }
    
    //encode_ipcc_body(encoder, precomputed, ipcontents, iplen, dir);
    //wandder_encoded_result_t * res = wandder_encode_finish(encoder);
    wandber_encoded_result_t * res = malloc(sizeof *res);
    res->buf = (*hdr)->block_0.buf;
    res->length = (*hdr)->totallen;
    return res;
}

int main(int argc, char *argv[])
{
    int runtimes = strtod(argv[1],NULL);

    etsili_intercept_details_t details;
    details.liid           = "liid"; 
    details.authcc         = "authcc";
    details.delivcc        = "delivcc";
    details.intpointid     = "intpointid";
    details.operatorid     = "operatorid";
    details.networkelemid  = "networkelemid";

    wandder_buf_t **preencoded_ber = calloc(OPENLI_PREENCODE_LAST, sizeof preencoded_ber);

    printf("prencoding..........");
    TIMEFUNC(
            {   //function to time
                etsili_preencode_static_fields_ber(preencoded_ber, &details);
            },
            {   //reset code
                etsili_clear_preencoded_fields_ber(preencoded_ber);
            }, 
            runtimes)
    
    etsili_preencode_static_fields_ber(preencoded_ber, &details);

    wandber_encoded_result_t *res_ber;
    
    int64_t cin = 0xfeedbeef;
    int64_t seqno = 0xdead;
    struct timeval tv;
    tv.tv_sec = 0xBADCAFE;
    tv.tv_usec = 0x1337;
    char* ipcontents = "this is the ippc body or the ipcontents";
    uint32_t iplen = strlen(ipcontents);
    uint8_t dir = 0x42;

    wandder_pshdr_t *hdrspace = NULL;
    wandder_pshdr_t **hdr = &hdrspace;

    res_ber = encode_etsi_ipcc(preencoded_ber, cin, seqno, &tv, ipcontents, iplen, dir, hdr);
    if ((*hdr)->totallen == sizeof trueResult){
        for (int i = 0; i < sizeof trueResult; i++){
            if (trueResult[i] != *(uint8_t *)(res_ber->buf+i)){
                printf("elemetn : %d\n", i);
                PRINTBUF(res_ber->buf, res_ber->length)
                assert(0);
            }
        }
    } else {
        printf("\n");
        PRINTBUF((*hdr)->block_0.buf, (*hdr)->totallen)
        printf("\n");
        PRINTBUF(trueResult, sizeof trueResult);
        printf("\n");
        assert(0);
    }
    // if (res_ber->length == sizeof ipcc_truth){
    //     for (int i = 0; i< res_ber->length; i++){
    //         if (ipcc_truth[i] != *(uint8_t *)(res_ber->buf+i)){
    //             printf("elemetn : %d\n", i);
    //             PRINTBUF(res_ber->buf, res_ber->length)
    //             assert(0);
    //         }
    //     }
    // } else {
    //     PRINTBUF(res_ber->buf, res_ber->length)
    //     PRINTBUF(ipcc_truth, sizeof ipcc_truth);
    //     assert(0);
    // }    
    printf("Passed test.\n");
    free(res_ber);
    res_ber = NULL;
    free((*hdr)->block_0.buf);
    free(*hdr);
    *hdr = NULL;
    
    if (runtimes != 0){
        printf("encoding firsttime..");
        TIMEFUNC(
            {   //function to time
                res_ber = encode_etsi_ipcc(preencoded_ber, cin, seqno, &tv, ipcontents, iplen, dir, hdr);
            },
            {   //reset code
                free(res_ber);
                res_ber = NULL;
                free((*hdr)->block_0.buf);
                free(*hdr);
                *hdr = NULL;
                cin = rand() >> (rand() % 64);
                seqno = rand() >> (rand() % 64);
                gettimeofday(&tv, NULL);
            }, 
            runtimes)

        gettimeofday(&tv, NULL);
        res_ber = encode_etsi_ipcc(preencoded_ber, cin, seqno, &tv, ipcontents, iplen, dir, hdr);
        free(res_ber);
        res_ber = NULL;
        cin = rand() >> (rand() % 64);
        seqno = rand() >> (rand() % 64);
        gettimeofday(&tv, NULL);

        printf("update encoding.....");
        TIMEFUNC(
            {   //function to time
                res_ber = encode_etsi_ipcc(preencoded_ber, cin, seqno, &tv, ipcontents, iplen, dir, hdr);
            },
            {   //reset code
                free(res_ber);
                res_ber = NULL;
                cin = rand() >> (rand() % 64);
                seqno = rand() >> (rand() % 64);
                gettimeofday(&tv, NULL);
            }, 
            runtimes)

    }

    free((*hdr)->block_0.buf);
    free(*hdr);

    etsili_clear_preencoded_fields_ber(preencoded_ber);
    free(preencoded_ber);

    return 0;
}

