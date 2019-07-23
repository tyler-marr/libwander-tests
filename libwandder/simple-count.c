

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
        printf("prencoding..........");
        etsili_clear_preencoded_fields_ber(preencoded_ber);
        TIMEFUNC(
                {   //function to time
                    etsili_preencode_static_fields_ber(preencoded_ber, &details);
                },
                {   //reset code
                    etsili_clear_preencoded_fields_ber(preencoded_ber);
                }, 
                runtimes)
        etsili_preencode_static_fields_ber(preencoded_ber, &details);

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
        free((*hdr)->block_0.buf);
        free(*hdr);
    }



    etsili_clear_preencoded_fields_ber(preencoded_ber);
    free(preencoded_ber);

    return 0;
}

