

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
                0x88, 0x01, 0x01, 
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

static inline wandder_pshdr_t * init_pshdr_pc(wandder_encode_job_t *precomputed, int64_t cin,
        int64_t seqno, struct timeval *tv) {

    /* hdrdata should be pretty static for each ETSI LI record, so
     * you can populate it once and repeatedly use it.
     * CIN, seqno and tv will change for each record, so I've made them
     * into separate parameters.
     */
    wandder_pshdr_t *header = malloc(sizeof(wandder_pshdr_t));
    uint8_t *freetemp;
    uint32_t ret;
    wandber_encoded_result_t *res_ber;  
    wandber_encoder_t *enc_ber = init_wandber_encoder();
    wandder_encode_job_t *jobarray[9];


    //////////////////////////////////////////////////////////////// block 0
    jobarray[0] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_1]);
    jobarray[1] = &(precomputed[OPENLI_PREENCODE_PSDOMAINID]);
    jobarray[2] = &(precomputed[OPENLI_PREENCODE_LIID]);
    jobarray[3] = &(precomputed[OPENLI_PREENCODE_AUTHCC]);
    jobarray[4] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_3]);
    jobarray[5] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_0]);
    jobarray[6] = &(precomputed[OPENLI_PREENCODE_OPERATORID]);
    jobarray[7] = &(precomputed[OPENLI_PREENCODE_NETWORKELEMID]);

    wandber_encode_next_preencoded(enc_ber, jobarray, 8);
    wandber_encode_endseq_repeat(enc_ber, 1);    
    
    res_ber = wandber_encode_finish(enc_ber);

    header->block_0.buf = res_ber->buf;
    header->block_0.len = res_ber->length;
    free(res_ber);
    res_ber = NULL;
    //////////////////////////////////////////////////////////////// cin
    ret = ber_create_integer(
        WANDDER_CLASS_CONTEXT_PRIMITIVE, 
        1, 
        &(cin), 
        sizeof(int64_t),
        &header->cin);
    header->cin.len = ret;    
    //////////////////////////////////////////////////////////////// block 1
    jobarray[0] = &(precomputed[OPENLI_PREENCODE_DELIVCC]);

    wandber_encode_next_preencoded(enc_ber, jobarray, 1);
    wandber_encode_endseq_repeat(enc_ber, 1);
    res_ber = wandber_encode_finish(enc_ber); 

    header->block_1.buf = res_ber->buf;
    header->block_1.len = res_ber->length;
    free(res_ber);
    res_ber = NULL;
    //////////////////////////////////////////////////////////////// seqno
    ret = ber_create_integer(
        WANDDER_CLASS_CONTEXT_PRIMITIVE, 
        4, 
        &(seqno), 
        sizeof(int64_t),
        &header->seqno);
    header->seqno.len = ret;
    //////////////////////////////////////////////////////////////// block 2
    if (precomputed[OPENLI_PREENCODE_INTPOINTID].valspace) {
        jobarray[0] = &(precomputed[OPENLI_PREENCODE_INTPOINTID]);
        jobarray[1] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_7]);
        wandber_encode_next_preencoded(enc_ber, jobarray, 2);
    } else {
        jobarray[0] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_7]);
        wandber_encode_next_preencoded(enc_ber, jobarray, 1);
    }
    res_ber = wandber_encode_finish(enc_ber);

    header->block_2.buf = res_ber->buf;
    header->block_2.len = res_ber->length;
    free(res_ber);
    res_ber = NULL;
    //////////////////////////////////////////////////////////////// tv_utimesec
    ret = ber_create_integer(
        WANDDER_CLASS_CONTEXT_PRIMITIVE, 
        0, 
        &(tv->tv_sec), 
        sizeof(tv->tv_sec),
        &header->sec);
    header->sec.len = ret;

    ret = ber_create_integer(
        WANDDER_CLASS_CONTEXT_PRIMITIVE, 
        1, 
        &(tv->tv_usec), 
        sizeof(tv->tv_usec),
        &header->usec);
    header->usec.len = ret;
    //////////////////////////////////////////////////////////////// block 3
    wandber_encode_endseq_repeat(enc_ber, 1);

    jobarray[0] = &(precomputed[OPENLI_PREENCODE_TVCLASS]);
    wandber_encode_next_preencoded(enc_ber, jobarray, 1);
    wandber_encode_endseq_repeat(enc_ber, 1);
    res_ber = wandber_encode_finish(enc_ber);

    header->block_3.buf = res_ber->buf;
    header->block_3.len = res_ber->length;
    free(res_ber);
    res_ber = NULL;
    //////////////////////////////////////////////////////////////// end
    free_wandber_encoder(enc_ber);


    //this some bullshit
    header->totallen = 
            header->block_0.len +
            header->cin.len + 
            header->block_1.len +
            header->seqno.len +
            header->block_2.len +
            header->sec.len +
            header->usec.len +
            header->block_3.len;
    freetemp = realloc(header->block_0.buf, header->totallen); //TODO avoid this large re-realloc
    header->block_0.buf = freetemp;


    freetemp = memcpy(
            header->block_0.buf + 
            header->block_0.len, 
            header->cin.buf, 
            header->cin.len);
    free(header->cin.buf);
    header->cin.buf = freetemp;

    freetemp = memcpy(
                header->cin.buf + 
                header->cin.len, 
                header->block_1.buf, 
                header->block_1.len);
    free(header->block_1.buf);
    header->block_1.buf = freetemp;

    freetemp = memcpy(
            header->block_1.buf + 
            header->block_1.len, 
            header->seqno.buf, 
            header->seqno.len);
    free(header->seqno.buf);
    header->seqno.buf = freetemp;

    freetemp = memcpy(
            header->seqno.buf + 
            header->seqno.len, 
            header->block_2.buf, 
            header->block_2.len);
    free(header->block_2.buf);
    header->block_2.buf = freetemp;

    freetemp = memcpy(
            header->block_2.buf + 
            header->block_2.len, 
            header->sec.buf, 
            header->sec.len);
    free(header->sec.buf);
    header->sec.buf = freetemp;

    freetemp = memcpy(
            header->sec.buf + 
            header->sec.len, 
            header->usec.buf, 
            header->usec.len);
    free(header->usec.buf);
    header->usec.buf = freetemp;

    freetemp = memcpy(
            header->usec.buf + 
            header->usec.len, 
            header->block_3.buf, 
            header->block_3.len);
    free(header->block_3.buf);
    header->block_3.buf = freetemp;
 
    return header;
}

static inline wandder_pshdr_t * init_pshdr_pc_ber(wandder_buf_t **precomputed, int64_t cin,
        int64_t seqno, struct timeval *tv) {

    /* hdrdata should be pretty static for each ETSI LI record, so
     * you can populate it once and repeatedly use it.
     * CIN, seqno and tv will change for each record, so I've made them
     * into separate parameters.
     */
    wandder_pshdr_t *header = malloc(sizeof(wandder_pshdr_t));
    uint8_t *freetemp;
    uint32_t ret;
    wandber_encoder_t *enc_ber = init_wandber_encoder();
    wandder_encode_job_t *jobarray[9];

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
    ptr+=2; //endseq
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
    ptr+= 2;//endseq
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
    ptr+=2;//endseq
    MEMCPYPREENCODE(ptr, precomputed[OPENLI_PREENCODE_TVCLASS]);
    ptr+=2;//endseq
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

void etsili_clear_preencoded_fields(wandder_encode_job_t *pendarray) {

    preencode_index_t i;

    for (i = 0; i < OPENLI_PREENCODE_LAST; i++) {
        if (pendarray[i].encodedspace) {
            free(pendarray[i].encodedspace);
        }
        if (pendarray[i].valspace) {
            free(pendarray[i].valspace);
        }
    }
}

void etsili_preencode_static_fields(
        wandder_encode_job_t *pendarray, etsili_intercept_details_t *details) {

    wandder_encode_job_t *p;
    int tvclass = 1;
    uint32_t dirin = 0, dirout = 1, dirunk = 2;

    memset(pendarray, 0, sizeof(wandder_encode_job_t) * OPENLI_PREENCODE_LAST);

    p = &(pendarray[OPENLI_PREENCODE_USEQUENCE]);
    p->identclass = WANDDER_CLASS_UNIVERSAL_CONSTRUCT;
    p->identifier = WANDDER_TAG_SEQUENCE;
    p->encodeas = WANDDER_TAG_SEQUENCE;
    p->valspace = NULL;
    p->vallen = 0;

    p = &(pendarray[OPENLI_PREENCODE_CSEQUENCE_0]);
    p->identclass = WANDDER_CLASS_CONTEXT_CONSTRUCT;
    p->identifier = 0;
    p->encodeas = WANDDER_TAG_SEQUENCE;
    p->valspace = NULL;
    p->vallen = 0;

    p = &(pendarray[OPENLI_PREENCODE_CSEQUENCE_1]);
    p->identclass = WANDDER_CLASS_CONTEXT_CONSTRUCT;
    p->identifier = 1;
    p->encodeas = WANDDER_TAG_SEQUENCE;
    p->valspace = NULL;
    p->vallen = 0;

    p = &(pendarray[OPENLI_PREENCODE_CSEQUENCE_2]);
    p->identclass = WANDDER_CLASS_CONTEXT_CONSTRUCT;
    p->identifier = 2;
    p->encodeas = WANDDER_TAG_SEQUENCE;
    p->valspace = NULL;
    p->vallen = 0;

    p = &(pendarray[OPENLI_PREENCODE_CSEQUENCE_3]);
    p->identclass = WANDDER_CLASS_CONTEXT_CONSTRUCT;
    p->identifier = 3;
    p->encodeas = WANDDER_TAG_SEQUENCE;
    p->valspace = NULL;
    p->vallen = 0;

    p = &(pendarray[OPENLI_PREENCODE_CSEQUENCE_7]);
    p->identclass = WANDDER_CLASS_CONTEXT_CONSTRUCT;
    p->identifier = 7;
    p->encodeas = WANDDER_TAG_SEQUENCE;
    p->valspace = NULL;
    p->vallen = 0;

    p = &(pendarray[OPENLI_PREENCODE_CSEQUENCE_11]);
    p->identclass = WANDDER_CLASS_CONTEXT_CONSTRUCT;
    p->identifier = 11;
    p->encodeas = WANDDER_TAG_SEQUENCE;
    p->valspace = NULL;
    p->vallen = 0;

    p = &(pendarray[OPENLI_PREENCODE_CSEQUENCE_12]);
    p->identclass = WANDDER_CLASS_CONTEXT_CONSTRUCT;
    p->identifier = 12;
    p->encodeas = WANDDER_TAG_SEQUENCE;
    p->valspace = NULL;
    p->vallen = 0;

    p = &(pendarray[OPENLI_PREENCODE_PSDOMAINID]);
    p->identclass = WANDDER_CLASS_CONTEXT_PRIMITIVE;
    p->identifier = 0;
    p->encodeas = WANDDER_TAG_OID;
    wandder_encode_preencoded_value(p, (uint8_t *)WANDDER_ETSILI_PSDOMAINID,
            sizeof(WANDDER_ETSILI_PSDOMAINID));

    p = &(pendarray[OPENLI_PREENCODE_LIID]);
    p->identclass = WANDDER_CLASS_CONTEXT_PRIMITIVE;
    p->identifier = 1;
    p->encodeas = WANDDER_TAG_OCTETSTRING;
    wandder_encode_preencoded_value(p, details->liid, strlen(details->liid));

    p = &(pendarray[OPENLI_PREENCODE_AUTHCC]);
    p->identclass = WANDDER_CLASS_CONTEXT_PRIMITIVE;
    p->identifier = 2;
    p->encodeas = WANDDER_TAG_OCTETSTRING;
    wandder_encode_preencoded_value(p, details->authcc, strlen(details->authcc));

    p = &(pendarray[OPENLI_PREENCODE_OPERATORID]);
    p->identclass = WANDDER_CLASS_CONTEXT_PRIMITIVE;
    p->identifier = 0;
    p->encodeas = WANDDER_TAG_OCTETSTRING;
    wandder_encode_preencoded_value(p, details->operatorid, strlen(details->operatorid));

    p = &(pendarray[OPENLI_PREENCODE_NETWORKELEMID]);
    p->identclass = WANDDER_CLASS_CONTEXT_PRIMITIVE;
    p->identifier = 1;
    p->encodeas = WANDDER_TAG_OCTETSTRING;
    wandder_encode_preencoded_value(p, details->networkelemid, strlen(details->networkelemid));

    p = &(pendarray[OPENLI_PREENCODE_DELIVCC]);
    p->identclass = WANDDER_CLASS_CONTEXT_PRIMITIVE;
    p->identifier = 2;
    p->encodeas = WANDDER_TAG_OCTETSTRING;
    wandder_encode_preencoded_value(p, details->delivcc, strlen(details->delivcc));

    p = &(pendarray[OPENLI_PREENCODE_INTPOINTID]);
    if (details->intpointid) {
        p->identclass = WANDDER_CLASS_CONTEXT_PRIMITIVE;
        p->identifier = 6;
        p->encodeas = WANDDER_TAG_OCTETSTRING;
        wandder_encode_preencoded_value(p, details->intpointid, strlen(details->intpointid));
    } else {
        p->valspace = NULL;
        p->vallen = 0;
    }

    p = &(pendarray[OPENLI_PREENCODE_TVCLASS]);
    p->identclass = WANDDER_CLASS_CONTEXT_PRIMITIVE;
    p->identifier = 8;
    p->encodeas = WANDDER_TAG_ENUM;
    wandder_encode_preencoded_value(p, &tvclass, sizeof(tvclass));

    p = &(pendarray[OPENLI_PREENCODE_IPMMIRIOID]);
    p->identclass = WANDDER_CLASS_CONTEXT_PRIMITIVE;
    p->identifier = 0;
    p->encodeas = WANDDER_TAG_RELATIVEOID;
    wandder_encode_preencoded_value(p, etsi_ipmmirioid, sizeof(etsi_ipmmirioid));

    p = &(pendarray[OPENLI_PREENCODE_IPCCOID]);
    p->identclass = WANDDER_CLASS_CONTEXT_PRIMITIVE;
    p->identifier = 0;
    p->encodeas = WANDDER_TAG_RELATIVEOID;
    wandder_encode_preencoded_value(p, etsi_ipccoid, sizeof(etsi_ipccoid));

    p = &(pendarray[OPENLI_PREENCODE_IPIRIOID]);
    p->identclass = WANDDER_CLASS_CONTEXT_PRIMITIVE;
    p->identifier = 0;
    p->encodeas = WANDDER_TAG_RELATIVEOID;
    wandder_encode_preencoded_value(p, etsi_ipirioid, sizeof(etsi_ipirioid));

    p = &(pendarray[OPENLI_PREENCODE_IPMMCCOID]);
    p->identclass = WANDDER_CLASS_CONTEXT_PRIMITIVE;
    p->identifier = 0;
    p->encodeas = WANDDER_TAG_RELATIVEOID;
    wandder_encode_preencoded_value(p, etsi_ipmmccoid, sizeof(etsi_ipmmccoid));

    p = &(pendarray[OPENLI_PREENCODE_DIRFROM]);
    p->identclass = WANDDER_CLASS_CONTEXT_PRIMITIVE;
    p->identifier = 0;
    p->encodeas = WANDDER_TAG_ENUM;
    wandder_encode_preencoded_value(p, &dirin, sizeof(dirin));

    p = &(pendarray[OPENLI_PREENCODE_DIRTO]);
    p->identclass = WANDDER_CLASS_CONTEXT_PRIMITIVE;
    p->identifier = 0;
    p->encodeas = WANDDER_TAG_ENUM;
    wandder_encode_preencoded_value(p, &dirout, sizeof(dirout));

    p = &(pendarray[OPENLI_PREENCODE_DIRUNKNOWN]);
    p->identclass = WANDDER_CLASS_CONTEXT_PRIMITIVE;
    p->identifier = 0;
    p->encodeas = WANDDER_TAG_ENUM;
    wandder_encode_preencoded_value(p, &dirunk, sizeof(dirunk));

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


    //TODO not 100% this is correct but i cant see anything wrong
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
            details->liid, 
            strlen(details->liid),
            NULL,
            0);
            
    
    pendarray[OPENLI_PREENCODE_AUTHCC] =  build_ber_field( 
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            2,
            WANDDER_TAG_OCTETSTRING,
            details->authcc, 
            strlen(details->authcc),
            NULL,
            0);
    
    pendarray[OPENLI_PREENCODE_OPERATORID] =  build_ber_field( 
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            0,
            WANDDER_TAG_OCTETSTRING,
            details->operatorid, 
            strlen(details->operatorid),
            NULL,
            0);

    pendarray[OPENLI_PREENCODE_NETWORKELEMID] =  build_ber_field( 
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            1,
            WANDDER_TAG_OCTETSTRING,
            details->networkelemid, 
            strlen(details->networkelemid),
            NULL,
            0);

    pendarray[OPENLI_PREENCODE_DELIVCC] =  build_ber_field( 
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            2,
            WANDDER_TAG_OCTETSTRING,
            details->delivcc, 
            strlen(details->delivcc),
            NULL,
            0);

    pendarray[OPENLI_PREENCODE_INTPOINTID] =  (details->intpointid) ? build_ber_field( 
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            6,
            WANDDER_TAG_OCTETSTRING,
            details->intpointid, 
            strlen(details->intpointid),
            NULL,
            0) : NULL;

    pendarray[OPENLI_PREENCODE_TVCLASS] =  build_ber_field( 
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            8,
            WANDDER_TAG_ENUM,
            &tvclass, 
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
            &dirin, 
            sizeof dirin,
            NULL,
            0);

    pendarray[OPENLI_PREENCODE_DIRTO] =  build_ber_field( 
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            0,
            WANDDER_TAG_ENUM,
            &dirout, 
            sizeof dirout,
            NULL,
            0);

    pendarray[OPENLI_PREENCODE_DIRUNKNOWN] =  build_ber_field( 
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            0,
            WANDDER_TAG_ENUM,
            &dirunk, 
            sizeof dirunk,
            NULL,
            0);

    for (int i = 0; i< OPENLI_PREENCODE_LAST -1; i++){
        //printf("%2d: 0x", i);
        PRINTBUF(pendarray[i]->buf, pendarray[i]->len);
    }
}

wandder_encoded_result_t *encode_etsi_ipcc(wandder_encoder_t *encoder,
        wandder_encode_job_t *precomputed, int64_t cin, int64_t seqno,
        struct timeval *tv, void *ipcontents, uint32_t iplen, uint8_t dir,
        wandder_pshdr_t **hdr) {

    if (*hdr){
        wandder_pshdr_update(cin, seqno, tv, *hdr);
    } else {
        *hdr = init_pshdr_pc(precomputed, cin, seqno, tv);
    }
    

    reset_wandder_encoder(encoder);
    encode_ipcc_body(encoder, precomputed, ipcontents, iplen, dir);
    wandder_encoded_result_t * res = wandder_encode_finish(encoder);
    return res;
}

wandder_encoded_result_t *encode_etsi_ipcc_ber(
        wandder_buf_t **precomputed, int64_t cin, int64_t seqno,
        struct timeval *tv, void *ipcontents, uint32_t iplen, uint8_t dir,
        wandder_pshdr_t **hdr) {

    if (*hdr){
        wandder_pshdr_update(cin, seqno, tv, *hdr);
    } else {
        *hdr = init_pshdr_pc_ber(precomputed, cin, seqno, tv);
    }
    
    printf("\n");
    PRINTBUF((*hdr)->block_0.buf, (*hdr)->block_0.len)
    PRINTBUF((*hdr)->cin.buf, (*hdr)->cin.len)
    PRINTBUF((*hdr)->block_1.buf, (*hdr)->block_1.len)
    PRINTBUF((*hdr)->seqno.buf, (*hdr)->seqno.len)
    PRINTBUF((*hdr)->block_2.buf, (*hdr)->block_2.len)
    PRINTBUF((*hdr)->sec.buf, (*hdr)->sec.len)
    PRINTBUF((*hdr)->usec.buf, (*hdr)->usec.len)
    PRINTBUF((*hdr)->block_3.buf, (*hdr)->block_3.len)
    printf("\n");
    PRINTBUF((*hdr)->block_0.buf, (*hdr)->totallen)
    //encode_ipcc_body(encoder, precomputed, ipcontents, iplen, dir);
    //wandder_encoded_result_t * res = wandder_encode_finish(encoder);
    return NULL;
}

int main(int argc, char *argv[])
{
    
    etsili_intercept_details_t details;
    details.liid           = "liid"; 
    details.authcc         = "authcc";
    details.delivcc        = "delivcc";
    details.intpointid     = "intpointid";
    details.operatorid     = "operatorid";
    details.networkelemid  = "networkelemid";    

    wandder_encode_job_t preencoded[OPENLI_PREENCODE_LAST];
    etsili_preencode_static_fields(preencoded, &details);


    wandder_buf_t preencoded_ber[OPENLI_PREENCODE_LAST] = {0};
    etsili_preencode_static_fields_ber(preencoded_ber, &details);

    wandder_encoder_t *encoder = init_wandder_encoder();
    wandder_encoded_result_t *res_der;
    wandber_encoded_result_t *res_ber;
    
    int64_t cin = 0xfeedbeef;
    int64_t seqno = 0xdead;
    struct timeval tv;
    tv.tv_sec = 0xBADCAFE;
    tv.tv_usec = 0x1337;
    char* ipcontents = "this is the ippc body or the ipcontents";
    uint32_t iplen = strlen(ipcontents);
    uint8_t dir = 0x42;
    
    

    //exit(0);
    wandder_pshdr_t *hdrspace = NULL;
    wandder_pshdr_t **hdr = &hdrspace;

    res_ber = encode_etsi_ipcc_ber(preencoded_ber, cin, seqno, &tv, ipcontents, iplen, dir, hdr);

    // res_der = encode_etsi_ipcc(encoder, preencoded, cin, seqno, &tv, ipcontents, iplen, dir, hdr);
    // if ((*hdr)->totallen == sizeof trueResult){
    //     for (int i = 0; i < sizeof trueResult; i++){
    //         if (trueResult[i] != *(uint8_t *)((*hdr)->block_0.buf+i)){
    //             printf("elemetn : %d\n", i);
    //             PRINTBUF((*hdr)->block_0.buf, (*hdr)->totallen)
    //             assert(0);
    //         }
    //     }
    // } else {
    //     PRINTBUF((*hdr)->block_0.buf, (*hdr)->totallen)
    //     PRINTBUF(trueResult, sizeof trueResult);
    //     assert(0);
    // }
    // if (res_der->len == sizeof ipcc_truth){
    //     for (int i = 0; i< res_der->len; i++){
    //         if (ipcc_truth[i] != *(uint8_t *)(res_der->encoded+i)){
    //             printf("elemetn : %d\n", i);
    //             PRINTBUF(res_der->encoded, res_der->len)
    //             assert(0);
    //         }
    //     }
    // } else {
    //     PRINTBUF(res_der->encoded, res_der->len)
    //     assert(0);
    // }    
    // printf("Passed test.\n");

    // wandder_release_encoded_result(encoder, res_der);
    // res_der = NULL;
    // free((*hdr)->block_0.buf);
    // free(*hdr);
    // *hdr = NULL;
    
    // int runtimes = strtod(argv[1],NULL);
    // if (runtimes != 0){    
    //     TIMEFUNC(
    //         {   //function to time
    //             res_der = encode_etsi_ipcc(encoder,
    //                 preencoded, cin, seqno,
    //                 &tv, ipcontents, iplen, dir, hdr);
    //         },
    //         {   //reset code
    //             wandder_release_encoded_result(encoder, res_der);
    //             res_der = NULL;
    //             free((*hdr)->block_0.buf);
    //             free(*hdr);
    //             *hdr = NULL;
    //             cin = rand() >> (rand() % 64);
    //             seqno = rand() >> (rand() % 64);
    //             gettimeofday(&tv, NULL);
    //         }, 
    //         runtimes)

    //     gettimeofday(&tv, NULL);
    //     res_der = encode_etsi_ipcc(encoder, preencoded, cin, seqno, &tv, ipcontents, iplen, dir, hdr);
    //     wandder_release_encoded_result(encoder, res_der);
    //     res_der = NULL;
    //     cin = rand() >> (rand() % 64);
    //     seqno = rand() >> (rand() % 64);
    //     gettimeofday(&tv, NULL);

    //     TIMEFUNC(
    //         {   //function to time
    //             res_der = encode_etsi_ipcc(encoder,
    //                 preencoded, cin, seqno,
    //                 &tv, ipcontents, iplen, dir, hdr);
    //         },
    //         {   //reset code
    //             wandder_release_encoded_result(encoder, res_der);
    //             res_der = NULL;
    //             cin = rand() >> (rand() % 64);
    //             seqno = rand() >> (rand() % 64);
    //             gettimeofday(&tv, NULL);
    //         }, 
    //         runtimes)

    //     free((*hdr)->block_0.buf);
    //     free(*hdr);
    // }

    // etsili_clear_preencoded_fields(preencoded);
    // free_wandder_encoder(encoder);

    return 0;
}

