

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
    printf("took avg:%6lu over %d samples\n",total/samples, num);}

char* MALSTR(char * s){
    char * ret = malloc(strlen(s) + 1); 
    strcpy(ret, s);
    return ret;

}

uint8_t etsi_ipccoid[4] = {0x05, 0x03, 0x0a, 0x02};
uint8_t etsi_ipirioid[4] = {0x05, 0x03, 0x0a, 0x01};
uint8_t etsi_ipmmccoid[4] = {0x05, 0x05, 0x06, 0x02};
uint8_t etsi_ipmmirioid[4] = {0x05, 0x05, 0x06, 0x01};
uint8_t trueResult[] = {
            0xa1, 0x80, 0x80, 0x08, 0x04, 0x00, 0x02, 0x02, 
            0x05, 0x01, 0x11, 0x00, 0x81, 0x04, 0x6c, 0x69, 
            0x69, 0x64, 0x82, 0x06, 0x61, 0x75, 0x74, 0x68,
            0x63, 0x63, 0xa3, 0x80, 0xa0, 0x80, 0x80, 0x0a,
            0x6f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x6f, 0x72,
            0x69, 0x64, 0x81, 0x0d, 0x6e, 0x65, 0x74, 0x77,
            0x6f, 0x72, 0x6b, 0x65, 0x6c, 0x65, 0x6d, 0x69,
            0x64, 0x00, 0x00, 0x81, 0x85, 0x00, 0x00, 0x00,
            0x00, 0x03, 0x01, 0xe2, 0x40, 0x82, 0x07, 0x64,
            0x65, 0x6c, 0x69, 0x76, 0x63, 0x63, 0x00, 0x00,
            0x84, 0x85, 0x00, 0x00, 0x00, 0x00, 0x03, 0x09,
            0xfb, 0xf1, 0x86, 0x0a, 0x69, 0x6e, 0x74, 0x70,
            0x6f, 0x69, 0x6e, 0x74, 0x69, 0x64, 0xa7, 0x80,
            0x80, 0x84, 0x00, 0x00, 0x00, 0x04, 0x2e, 0x22,
            0x85, 0xc0, 0x81, 0x86, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02, 0x13, 0x37, 0x00, 0x00, 0x88, 0x01,
            0x01, 0x00, 0x00};

typedef struct wandder_pshdr {
    uint32_t totallen;

    wandder_buf_t *block_0;

    wandder_buf_t *cin;

    wandder_buf_t *block_1;

    wandder_buf_t *seqno;

    wandder_buf_t *block_2;

    wandder_buf_t *sec;

    wandder_buf_t *usec;

    wandder_buf_t *block_3;

} wandder_pshdr_t;

void wandder_pshdr_update(int64_t cin,
        int64_t seqno, struct timeval *tv, wandder_pshdr_t * hdr) {

    uint32_t ret = 0;

    ret = ber_rebuild_integer(
        WANDDER_CLASS_CONTEXT_PRIMITIVE, 
        1, 
        &(cin), 
        sizeof(int64_t),
        hdr->cin->buf);

    ret = ber_rebuild_integer(
        WANDDER_CLASS_CONTEXT_PRIMITIVE, 
        4, 
        &(seqno), 
        sizeof(int64_t),
        hdr->seqno->buf);

    ret = ber_rebuild_integer(
        WANDDER_CLASS_CONTEXT_PRIMITIVE, 
        0, 
        &(tv->tv_sec), 
        sizeof(tv->tv_sec),
        hdr->sec->buf);

    ret = ber_rebuild_integer(
        WANDDER_CLASS_CONTEXT_PRIMITIVE, 
        1, 
        &(tv->tv_usec), 
        sizeof(tv->tv_usec),
        hdr->usec->buf);
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
    //uses an array to only need a single call to calloc
    wandder_pshdr_t *header = malloc(sizeof(wandder_pshdr_t));
    // header->block_0 = calloc(sizeof (wandder_buf_t), 8);
    // header->cin     = &header->block_0[1];
    // header->block_1 = &header->block_0[2];
    // header->seqno   = &header->block_0[3];
    // header->block_2 = &header->block_0[4];
    // header->sec     = &header->block_0[5];
    // header->usec    = &header->block_0[6];
    // header->block_3 = &header->block_0[7];

    header->block_0 = calloc(sizeof (wandder_buf_t), 1);
    header->cin     = calloc(sizeof (wandder_buf_t), 1);
    header->block_1 = calloc(sizeof (wandder_buf_t), 1); 
    header->seqno   = calloc(sizeof (wandder_buf_t), 1);
    header->block_2 = calloc(sizeof (wandder_buf_t), 1);
    header->sec     = calloc(sizeof (wandder_buf_t), 1);
    header->usec    = calloc(sizeof (wandder_buf_t), 1);
    header->block_3 = calloc(sizeof (wandder_buf_t), 1);

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

    header->block_0->buf = res_ber->buf;
    header->block_0->len = res_ber->length;
    free(res_ber);
    res_ber = NULL;
    //////////////////////////////////////////////////////////////// cin
    // wandber_encode_next(enc_ber, WANDDER_TAG_INTEGER,
    //         WANDDER_CLASS_CONTEXT_PRIMITIVE, 1, &(cin),
    //         sizeof(int64_t));
    // res_ber = wandber_encode_finish(enc_ber);
    // header->cin->buf = res_ber->buf;
    // header->cin->len = res_ber->length;
    // free(res_ber);
    // res_ber = NULL;

    ret = ber_create_integer(
        WANDDER_CLASS_CONTEXT_PRIMITIVE, 
        1, 
        &(cin), 
        sizeof(int64_t),
        header->cin);
    header->cin->len = ret;  
    
    //////////////////////////////////////////////////////////////// block 1
    jobarray[0] = &(precomputed[OPENLI_PREENCODE_DELIVCC]);
    wandber_encode_next_preencoded(enc_ber, jobarray, 1);
    wandber_encode_endseq_repeat(enc_ber, 1);
    res_ber = wandber_encode_finish(enc_ber); 

    header->block_1->buf = res_ber->buf;
    header->block_1->len = res_ber->length;
    free(res_ber);
    res_ber = NULL;
    //////////////////////////////////////////////////////////////// seqno
    // wandber_encode_next(enc_ber, WANDDER_TAG_INTEGER,
    //         WANDDER_CLASS_CONTEXT_PRIMITIVE, 4, &(seqno),
    //         sizeof(int64_t));
    // res_ber = wandber_encode_finish(enc_ber); 

    // header->seqno->buf = res_ber->buf;
    // header->seqno->len = res_ber->length;
    // free(res_ber);
    // res_ber = NULL;

    ret = ber_create_integer(
        WANDDER_CLASS_CONTEXT_PRIMITIVE, 
        4, 
        &(seqno), 
        sizeof(int64_t),
        header->seqno);
    header->seqno->len = ret;

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

    header->block_2->buf = res_ber->buf;
    header->block_2->len = res_ber->length;
    free(res_ber);
    res_ber = NULL;
    //////////////////////////////////////////////////////////////// tv_utimesec
    // wandber_encode_next(enc_ber, WANDDER_TAG_INTEGER,
    //         WANDDER_CLASS_CONTEXT_PRIMITIVE, 0, &(tv->tv_sec),
    //         sizeof(tv->tv_sec));
    // res_ber = wandber_encode_finish(enc_ber);
    // header->sec->buf = res_ber->buf;
    // header->sec->len = res_ber->length;
    // free(res_ber);
    // res_ber = NULL;

    // wandber_encode_next(enc_ber, WANDDER_TAG_INTEGER,
    //         WANDDER_CLASS_CONTEXT_PRIMITIVE, 1, &(tv->tv_usec),
    //         sizeof(tv->tv_usec));
    // res_ber = wandber_encode_finish(enc_ber);
    // header->usec->buf = res_ber->buf;
    // header->usec->len = res_ber->length;
    // free(res_ber);
    // res_ber = NULL;


    ret = ber_create_integer(
        WANDDER_CLASS_CONTEXT_PRIMITIVE, 
        0, 
        &(tv->tv_sec), 
        sizeof(tv->tv_sec),
        header->sec);
    header->sec->len = ret;

    ret = ber_create_integer(
        WANDDER_CLASS_CONTEXT_PRIMITIVE, 
        1, 
        &(tv->tv_usec), 
        sizeof(tv->tv_usec),
        header->usec);
    header->usec->len += ret;

    //////////////////////////////////////////////////////////////// block 3
    wandber_encode_endseq_repeat(enc_ber, 1);

    jobarray[0] = &(precomputed[OPENLI_PREENCODE_TVCLASS]);
    wandber_encode_next_preencoded(enc_ber, jobarray, 1);
    wandber_encode_endseq_repeat(enc_ber, 1);
    res_ber = wandber_encode_finish(enc_ber);

    header->block_3->buf = res_ber->buf;
    header->block_3->len = res_ber->length;
    free(res_ber);
    res_ber = NULL;
    //////////////////////////////////////////////////////////////// end
    free_wandber_encoder(enc_ber);


    //this some bullshit
    header->totallen = 
            header->block_0->len +
            header->cin->len + 
            header->block_1->len +
            header->seqno->len +
            header->block_2->len +
            header->sec->len +
            header->usec->len +
            header->block_3->len;
    freetemp = realloc(header->block_0->buf, header->totallen);
    header->block_0->buf = freetemp;


    freetemp = memcpy(
            header->block_0->buf + 
            header->block_0->len, 
            header->cin->buf, 
            header->cin->len);
    free(header->cin->buf);
    header->cin->buf = freetemp;

    freetemp = memcpy(
                header->cin->buf + 
                header->cin->len, 
                header->block_1->buf, 
                header->block_1->len);
    free(header->block_1->buf);
    header->block_1->buf = freetemp;

    freetemp = memcpy(
            header->block_1->buf + 
            header->block_1->len, 
            header->seqno->buf, 
            header->seqno->len);
    free(header->seqno->buf);
    header->seqno->buf = freetemp;

    freetemp = memcpy(
            header->seqno->buf + 
            header->seqno->len, 
            header->block_2->buf, 
            header->block_2->len);
    free(header->block_2->buf);
    header->block_2->buf = freetemp;

    freetemp = memcpy(
            header->block_2->buf + 
            header->block_2->len, 
            header->sec->buf, 
            header->sec->len);
    free(header->sec->buf);
    header->sec->buf = freetemp;

    freetemp = memcpy(
            header->sec->buf + 
            header->sec->len, 
            header->usec->buf, 
            header->usec->len);
    free(header->usec->buf);
    header->usec->buf = freetemp;

    freetemp = memcpy(
            header->usec->buf + 
            header->usec->len, 
            header->block_3->buf, 
            header->block_3->len);
    free(header->block_3->buf);
    header->block_3->buf = freetemp;
 
    // printf("TOTAL:\n");
    // PRINTBUF(header->block_0, header->block_0_len)
    // printf("\n");
    // PRINTBUF(header->cin, header->cin_len)
    // printf("\n");
    // PRINTBUF(header->block_1, header->block_1_len)
    // printf("\n");
    // PRINTBUF(header->seqno, header->seqno_len)
    // printf("\n");
    // PRINTBUF(header->block_2, header->block_2_len)
    // printf("\n");
    // PRINTBUF(header->sec, header->time_len)
    // printf("\n");
    // PRINTBUF(header->usec, header->time_len)
    // printf("\n");
    // PRINTBUF(header->block_3, header->block_3_len)
    // printf("\n");
    // printf("All together:\n");
    // PRINTBUF(header->block_0, header->totallen)
    // printf("\n");

    return header;


}

static inline void encode_etsili_pshdr_pc(wandder_encoder_t *encoder,
        wandder_encode_job_t *precomputed, int64_t cin,
        int64_t seqno, struct timeval *tv) {

    /* hdrdata should be pretty static for each ETSI LI record, so
     * you can populate it once and repeatedly use it.
     * CIN, seqno and tv will change for each record, so I've made them
     * into separate parameters.
     */

    wandder_encode_job_t *jobarray[9];

    jobarray[0] = &(precomputed[OPENLI_PREENCODE_USEQUENCE]);
    jobarray[1] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_1]);
    jobarray[2] = &(precomputed[OPENLI_PREENCODE_PSDOMAINID]);
    jobarray[3] = &(precomputed[OPENLI_PREENCODE_LIID]);
    jobarray[4] = &(precomputed[OPENLI_PREENCODE_AUTHCC]);
    jobarray[5] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_3]);
    jobarray[6] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_0]);
    jobarray[7] = &(precomputed[OPENLI_PREENCODE_OPERATORID]);
    jobarray[8] = &(precomputed[OPENLI_PREENCODE_NETWORKELEMID]);

    wandder_encode_next_preencoded(encoder, jobarray, 9);
    END_ENCODED_SEQUENCE(encoder, 1)

    wandder_encode_next(encoder, WANDDER_TAG_INTEGER,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 1, &(cin),
            sizeof(int64_t));

    jobarray[0] = &(precomputed[OPENLI_PREENCODE_DELIVCC]);
    wandder_encode_next_preencoded(encoder, jobarray, 1);

    END_ENCODED_SEQUENCE(encoder, 1)

    wandder_encode_next(encoder, WANDDER_TAG_INTEGER,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 4, &(seqno),
            sizeof(int64_t));

    if (precomputed[OPENLI_PREENCODE_INTPOINTID].valspace) {
        jobarray[0] = &(precomputed[OPENLI_PREENCODE_INTPOINTID]);
        jobarray[1] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_7]);
        wandder_encode_next_preencoded(encoder, jobarray, 2);
    } else {
        jobarray[0] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_7]);
        wandder_encode_next_preencoded(encoder, jobarray, 1);
    }

    wandder_encode_next(encoder, WANDDER_TAG_INTEGER,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 0, &(tv->tv_sec),
            sizeof(tv->tv_sec));
    wandder_encode_next(encoder, WANDDER_TAG_INTEGER,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 1, &(tv->tv_usec),
            sizeof(tv->tv_usec));
    END_ENCODED_SEQUENCE(encoder, 1)

    jobarray[0] = &(precomputed[OPENLI_PREENCODE_TVCLASS]);
    wandder_encode_next_preencoded(encoder, jobarray, 1);
    END_ENCODED_SEQUENCE(encoder, 1)

}

static inline void encode_ipcc_body(wandder_encoder_t *encoder,
        wandder_encode_job_t *precomputed, void *ipcontent, uint32_t iplen,
        uint8_t dir) {

    uint32_t dir32 = dir;
    wandder_encode_job_t *jobarray[8];
    int nextjob = 0;

    jobarray[0] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_2]);
    jobarray[1] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_1]);
    jobarray[2] = &(precomputed[OPENLI_PREENCODE_USEQUENCE]);

    if (dir == 0) {
        jobarray[3] = &(precomputed[OPENLI_PREENCODE_DIRFROM]);
        nextjob = 4;
    } else if (dir == 1) {
        jobarray[3] = &(precomputed[OPENLI_PREENCODE_DIRTO]);
        nextjob = 4;
    } else if (dir == 2) {
        jobarray[3] = &(precomputed[OPENLI_PREENCODE_DIRUNKNOWN]);
        nextjob = 4;
    } else {
        wandder_encode_next_preencoded(encoder, jobarray, 4);
        nextjob = 0;
        wandder_encode_next(encoder, WANDDER_TAG_ENUM,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 0, &dir32,
                sizeof(uint32_t));
    }

    jobarray[nextjob] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_2]);
    nextjob ++;
    jobarray[nextjob] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_2]);
    nextjob ++;
    jobarray[nextjob] = &(precomputed[OPENLI_PREENCODE_IPCCOID]);
    nextjob ++;
    jobarray[nextjob] = &(precomputed[OPENLI_PREENCODE_CSEQUENCE_1]);
    nextjob ++;

    wandder_encode_next_preencoded(encoder, jobarray, nextjob);

    wandder_encode_next(encoder, WANDDER_TAG_IPPACKET,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 0, ipcontent, iplen);

    END_ENCODED_SEQUENCE(encoder, 7);

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

wandder_encoded_result_t *encode_etsi_ipcc(wandder_encoder_t *encoder,
        wandder_encode_job_t *precomputed, int64_t cin, int64_t seqno,
        struct timeval *tv, void *ipcontents, uint32_t iplen, uint8_t dir,
        wandder_pshdr_t **hdr) {


    reset_wandder_encoder(encoder);


    if (*hdr){
        wandder_pshdr_update(cin, seqno, tv, *hdr);
    } else {
        *hdr = init_pshdr_pc(precomputed, cin, seqno, tv);
    }

    //append hdr to start of encoder 

    // //printf("All together:\n");
    // PRINTBUF((*hdr)->block_0, (*hdr)->totallen)
    // printf("\n");
    
    encode_ipcc_body(encoder, precomputed, ipcontents, iplen, dir);
    wandder_encoded_result_t * res = wandder_encode_finish(encoder);
    return res;

}

int main(int argc, char *argv[])
{
        
    int fd = open("ipcchex", O_RDONLY);
    if(fd == -1){
        return -1;
    }

        
    struct stat st;
    fstat(fd, &st);
    int size = st.st_size;

    uint8_t *buf;
    buf = malloc(size * sizeof(uint8_t));

    read(fd, buf, size);

        // printf("Dump:");
        // for (int i = 0; i < size; i++){               
        //         if (i % 16 == 0){
        //                 printf("\n");
        //         }
        //         printf("%02x ", buf[i]);
        // }
        // printf("\nEND OF DUMP\n");

    
    etsili_intercept_details_t *details = malloc(sizeof (etsili_intercept_details_t));

    details->liid           = MALSTR("liid"); 
    details->authcc         = MALSTR("authcc");
    details->delivcc        = MALSTR("delivcc");
    details->intpointid     = MALSTR("intpointid");
    details->operatorid     = MALSTR("operatorid");
    details->networkelemid  = MALSTR("networkelemid");

    wandder_encode_job_t *preencoded = malloc(sizeof (wandder_encode_job_t)* OPENLI_PREENCODE_LAST);

    etsili_preencode_static_fields(preencoded, details);
    
    int64_t cin = 0xfeedbeef;
    int64_t seqno = 0xdead;
    struct timeval *tv = malloc(sizeof(struct timeval));
    gettimeofday(tv, NULL);

    char* ipcontents = MALSTR("this is the ippc body or the ipcontents");
    uint32_t iplen = strlen(ipcontents);
    uint8_t dir = 0;
    
    wandder_encoder_t *encoder = init_wandder_encoder();
    wandder_encoded_result_t *res_der;

    //exit(0);
    wandder_pshdr_t *hdrspace = NULL;
    wandder_pshdr_t **hdr = &hdrspace;

    tv->tv_sec = 0x2E2285C0;
    tv->tv_usec = 0x1337;
    res_der = encode_etsi_ipcc(encoder, preencoded, 123456, 654321, tv, ipcontents, iplen, dir, hdr);
    wandder_release_encoded_result(encoder, res_der);
    res_der = NULL;
    if ((*hdr)->totallen == sizeof trueResult){
        for (int i = 0; i< sizeof trueResult; i++){
            if (trueResult[i] != *(uint8_t *)((*hdr)->block_0->buf+i)){
                PRINTBUF((*hdr)->block_0->buf, (*hdr)->totallen)
                assert(0);
            }
        }
    } else {
        PRINTBUF((*hdr)->block_0->buf, (*hdr)->totallen)
        assert(0);
    }    
    printf("Passed test.\n");

    res_der = NULL;
    free((*hdr)->block_0->buf);
    free((*hdr)->block_0);
    free(*hdr);
    *hdr = NULL;
    cin = rand() >> (rand() % 64);
    seqno = rand() >> (rand() % 64);
    gettimeofday(tv, NULL);
    
    int runtimes = strtod(argv[1],NULL);
    
    TIMEFUNC(
        {
            res_der = encode_etsi_ipcc(encoder,
                preencoded, cin, seqno,
                tv, ipcontents, iplen, dir, hdr);
        },
        {
            wandder_release_encoded_result(encoder, res_der);
            res_der = NULL;
            free((*hdr)->block_0->buf);
            free((*hdr)->block_0);
            free(*hdr);
            *hdr = NULL;
            cin = rand() >> (rand() % 64);
            seqno = rand() >> (rand() % 64);
            gettimeofday(tv, NULL);
        }, 
        runtimes)

    gettimeofday(tv, NULL);
    res_der = encode_etsi_ipcc(encoder, preencoded, cin, seqno, tv, ipcontents, iplen, dir, hdr);
    wandder_release_encoded_result(encoder, res_der);
    res_der = NULL;
    cin = rand() >> (rand() % 64);
    seqno = rand() >> (rand() % 64);
    gettimeofday(tv, NULL);

    TIMEFUNC(
        {
            res_der = encode_etsi_ipcc(encoder,
                preencoded, cin, seqno,
                tv, ipcontents, iplen, dir, hdr);
        },
        {
            //if (res_der->len != 62) printf("Length:%d\n", res_der->len);
            wandder_release_encoded_result(encoder, res_der);
            res_der = NULL;



            cin = rand() >> (rand() % 64);
            seqno = rand() >> (rand() % 64);
            gettimeofday(tv, NULL);
        }, 
        runtimes)

    etsili_clear_preencoded_fields(preencoded);
    free(preencoded);
    free_wandder_encoder(encoder);
    free(details->liid);
    free(details->authcc);
    free(details->delivcc);
    free(details->intpointid);
    free(details->operatorid);
    free(details->networkelemid);
    free(details);
    free(ipcontents);
    free(tv);
    free((*hdr)->block_0->buf);
    free((*hdr)->block_0);
    free(*hdr);
    free(buf);
    buf = NULL;

    return 0;
}
