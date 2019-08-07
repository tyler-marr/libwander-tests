

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>

#include <libwandder.h>
#include <libwandder_etsili.h>

#define PRINTBUF(ptr,len) for (size_t uniuqevari = 0; uniuqevari< len; uniuqevari++)\
            printf("%02x ",*(uint8_t *)(ptr+uniuqevari));\
        printf("\n");

#define TIMEFUNC(func, reset, num) {                                                        \
    struct timespec start, end;                                                             \
    uint64_t delta_us = 0;                                                                  \
    uint64_t samples = 0;                                                                   \
    uint64_t total = 0;                                                                     \
    for (int uniuqevari = 0; uniuqevari < num; uniuqevari++){                               \
        clock_gettime(CLOCK_MONOTONIC, &start);                                             \
        func                                                                                \
       clock_gettime(CLOCK_MONOTONIC, &end);                                               \
        reset                                                                               \
        delta_us = (end.tv_sec - start.tv_sec) * 1000000000 + (end.tv_nsec - start.tv_nsec);\
        total += delta_us;                                                                  \
        samples++;                                                                          \
        if (total > (UINT64_MAX>>1)){                                                       \
            total = total/samples;                                                          \
            samples = 1;                                                                    \
        }                                                                                   \
    }                                                                                       \
    printf("took avg:%6luns over %d samples, ",total/samples , num);}


uint8_t true_header[] = {
        0x30, 0x80,
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

uint8_t true_ipcc[] = {
            0xa2, 0x80, 
                0xa1, 0x80,
                    0x30, 0x80,
                        0x80, 0x86, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x42, 
                        0xa2, 0x80, 
                            0xa2, 0x80, 
                                0x80, 0x04, 0x05, 0x03, 0x0a, 0x02,
                                0xa1, 0x80, 
                                    0x80, 0x27, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 
                                                0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
                                                0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 
                                                0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 
                                                0x00, 0x00, 0x00, 0x00,  0x00, 
                                    0x00, 0x00, 
                                0x00, 0x00, 
                            0x00, 0x00, 
                        0x00, 0x00, 
                    0x00, 0x00, 
                0x00, 0x00, 
            0x00, 0x00, 
        0x00, 0x00}; 
/*
[2] (1 elem)
    [1] (1 elem)
        SEQUENCE (2 elem)
            [0] B
            [2] (1 elem)
                [2] (2 elem)
                    [0] (4 byte) 05030A02
                    [1] (1 elem)
                        [0] (39 byte) 0000000000000000000000000000000000000000000000000000000000000000000000…
*/

uint8_t true_ipmmcc[] = {
            0xa2, 0x80, 
                0xa1, 0x80,
                    0x30, 0x80,
                        0x80, 0x86, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x42, 
                        0xa2, 0x80, 
                            0xac, 0x80,
                                0x80, 0x04, 0x05, 0x05, 0x06, 0x02,
                                0x80, 0x27, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 
                                            0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
                                            0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 
                                            0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 
                                            0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00,
                                0x82, 0x86, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
                                0x82, 0x86, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
                            0x00, 0x00, 
                        0x00, 0x00, 
                    0x00, 0x00, 
                0x00, 0x00, 
            0x00, 0x00, 
        0x00, 0x00}; 
/*
[2] (1 elem)
  [1] (1 elem)
    SEQUENCE (2 elem)
      [0] B
      [2] (1 elem)
        [12] (4 elem)
          [0] (4 byte) 05050602
          [0] (39 byte) 0000000000000000000000000000000000000000000000000000000000000000000000…
          [2] (1 byte) 00
          [2] (1 byte) 00
*/


uint8_t true_ipmmiri[] = {
            0xa2, 0x80, 
                0xa1, 0x80,
                    0x30, 0x80,
                        0x80, 0x86, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x42, 
                        0xa2, 0x80, 
                            0xa1, 0x80,
                                0x80, 0x04, 0x05, 0x05, 0x06, 0x01,
                                0xa1, 0x80,
                                    0x80, 0x27, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 
                                                0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
                                                0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 
                                                0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 
                                                0x00, 0x00, 0x00, 0x00,  0x00, 
                                    0x00, 0x00, 
                                0x00, 0x00, 
                            0x00, 0x00, 
                        0x00, 0x00, 
                    0x00, 0x00, 
                0x00, 0x00,
            0x00, 0x00,
        0x00, 0x00};
/*
[2] (1 elem)
    [0] (1 elem)
        SEQUENCE (2 elem)
            [0] B
            [2] (1 elem)
                [1] (2 elem)
                    [0] (4 byte) 05050601
                    [1] (1 elem)
                        [0] (39 byte) 0000000000000000000000000000000000000000000000000000000000000000000000…
*/

int runtimes = 0;

void test_encoding(
        void (*fun_ptr)(wandder_buf_t **, int64_t, int64_t,
            struct timeval *, void *, size_t, uint8_t,
            wandder_etsili_top_t *), 
        wandder_buf_t **preencoded_ber, wandder_buf_t true_body){

    int64_t cin = 0xfeedbeef;
    int64_t seqno = 0xdead;
    struct timeval tv;
    tv.tv_sec = 0xBADCAFE;
    tv.tv_usec = 0x1337;
    char* ipcontentsstring = "this is the ippc body or the ipcontents";
    uint32_t iplen = strlen(ipcontentsstring);
    uint8_t ipcontents[1000] = {3};
    memcpy(ipcontents, ipcontentsstring, iplen);
    uint8_t dir = 0x42; //doubles as iritype

    wandder_etsili_top_t top;
    memset(&top, 0, sizeof top);
    
    

    (*fun_ptr)(preencoded_ber, cin, seqno, &tv, ipcontents, iplen, dir, &top);

    for (size_t i = 0; i < sizeof true_header; i++){
        uint8_t trueval =  *(uint8_t*)(true_header+i);
        uint8_t actualval = *(top.buf + i);
        //if (true_header[i] != *(uint8_t *)(top.buf+i)){
        if (trueval != actualval){
            PRINTBUF(top.buf, sizeof true_header)
            printf("elemetn %ld in header differs, true[0x%02x], actual[0x%02x]\n", i, trueval, actualval);
            PRINTBUF(true_header, sizeof true_header)
            assert(0);
        }
    }
    printf("header test done\n");

    for (size_t i = 0; i< true_body.len; i++){
        uint8_t trueval =  *(uint8_t*)((true_body.buf)+i);
        uint8_t actualval = *((top.buf + sizeof true_header)+i);
        if (trueval != actualval){
            printf("elemetn %ld in body differs, true[0x%02x], actual[0x%02x]\n", i, trueval, actualval);
            PRINTBUF(top.buf + sizeof true_header, top.len - sizeof true_header)
            printf("\n");
            PRINTBUF(true_body.buf, true_body.len);
            assert(0);
        }
    }
    if (true_body.len + sizeof true_header != top.len){
        printf("true size = %4ld, actual size = %4ld\n", true_body.len + sizeof true_header, top.len);
        PRINTBUF(top.buf, top.len)
        assert(0);
    }
    printf("Passed test.\n");
    free(top.buf);
    memset(&top, 0, sizeof top);

    
    if (runtimes != 0){

        printf("encoding firsttime..");
        TIMEFUNC(
            {   //function to time
                (*fun_ptr)(preencoded_ber, cin, seqno, &tv, ipcontents, iplen, dir, &top);
            },
            {   //reset code
                free(top.buf);
                memset(&top, 0, sizeof top);
                cin = rand() >> (rand() % 64);
                seqno = rand() >> (rand() % 64);
                iplen = rand() % 1000;
                dir = rand() %3;
                gettimeofday(&tv, NULL);
            }, 
            runtimes)
        printf("Needs to be done once per stream\n");

        gettimeofday(&tv, NULL);
        (*fun_ptr)(preencoded_ber, cin, seqno, &tv, ipcontents, iplen, dir, &top);
        // free(top.buf);
        // memset(&top, 0, sizeof top);
        cin = rand() >> (rand() % 64);
        seqno = rand() >> (rand() % 64);
        iplen = rand() % 1000;
        dir = rand() %3;
        gettimeofday(&tv, NULL);

        printf("update encoding.....");
        TIMEFUNC(
            {   //function to time
                (*fun_ptr)(preencoded_ber, cin, seqno, &tv, ipcontents, iplen, dir, &top);
            },
            {   //reset code
                cin = rand() >> (rand() % 64);
                seqno = rand() >> (rand() % 64);
                iplen = rand() % 1000;
                dir = rand() %3;
                gettimeofday(&tv, NULL);
            }, 
            runtimes)
        printf("Needs to be done everytime\n");
        free(top.buf);
        memset(&top, 0, sizeof top);
    }
}

void new_metho_ipcc(wandder_buf_t** preencoded_ber, int64_t cin, int64_t seqno,
        struct timeval* tv, void* ipcontents, size_t iplen, uint8_t dir,
        wandder_etsili_top_t* top){

    if (top->buf){
        //printf("IT ALREADY EXITS\n");
        // ber_rebuild_integer(
        //     WANDDER_CLASS_CONTEXT_PRIMITIVE, 
        //     1, 
        //     &(cin), 
        //     sizeof cin,
        //     top->header.cin);

        // ber_rebuild_integer(
        //     WANDDER_CLASS_CONTEXT_PRIMITIVE, 
        //     4, 
        //     &(seqno), 
        //     sizeof seqno,
        //     top->header.seqno);

        // ber_rebuild_integer(
        //     WANDDER_CLASS_CONTEXT_PRIMITIVE, 
        //     0, 
        //     &(tv->tv_sec), 
        //     sizeof tv->tv_sec,
        //     top->header.sec);

        // ber_rebuild_integer(
        //     WANDDER_CLASS_CONTEXT_PRIMITIVE, 
        //     1, 
        //     &(tv->tv_usec), 
        //     sizeof tv->tv_usec,
        //     top->header.usec);
        
        ///////

    if (dir == 0) {
        memcpy(top->body.ipcc.dir, preencoded_ber[WANDDER_PREENCODE_DIRFROM]->buf, preencoded_ber[WANDDER_PREENCODE_DIRFROM]->len);
    } else if (dir == 1) {
        memcpy(top->body.ipcc.dir, preencoded_ber[WANDDER_PREENCODE_DIRTO]->buf, preencoded_ber[WANDDER_PREENCODE_DIRTO]->len);
    } else if (dir == 2) {
        memcpy(top->body.ipcc.dir, preencoded_ber[WANDDER_PREENCODE_DIRUNKNOWN]->buf, preencoded_ber[WANDDER_PREENCODE_DIRUNKNOWN]->len);
    } else {
        // ber_rebuild_integer(
        //     WANDDER_CLASS_CONTEXT_PRIMITIVE, 
        //     0, 
        //     &(dir), 
        //     sizeof dir,
        //     top->body.ipcc.dir);
    }
    //uint8_t * ptr = top->body.ipcc.ipcontent;
    // ptr += wandder_encode_inplace_ber(WANDDER_CLASS_CONTEXT_PRIMITIVE, 
    //         0,
    //         WANDDER_TAG_IPPACKET,
    //         ipcontents, 
    //         iplen,
    //         top->body.ipcc.ipcontent,
    //         top->alloc_len - (ptr - top->buf));

    // ENDCONSTRUCTEDBLOCK(ptr,7) //endseq

    }
    else {

        wandder_encoder_ber_t* enc_ber = wandder_init_encoder_ber(1000, 0);
        wandder_encoded_result_ber_t* res_ber;

        wandder_append_preencoded_ber(enc_ber, preencoded_ber[WANDDER_PREENCODE_USEQUENCE]);
        wandder_append_preencoded_ber(enc_ber, preencoded_ber[WANDDER_PREENCODE_CSEQUENCE_1]);
        wandder_append_preencoded_ber(enc_ber, preencoded_ber[WANDDER_PREENCODE_PSDOMAINID]);
        wandder_append_preencoded_ber(enc_ber, preencoded_ber[WANDDER_PREENCODE_LIID]);
        wandder_append_preencoded_ber(enc_ber, preencoded_ber[WANDDER_PREENCODE_AUTHCC]);
        wandder_append_preencoded_ber(enc_ber, preencoded_ber[WANDDER_PREENCODE_CSEQUENCE_3]);
        wandder_append_preencoded_ber(enc_ber, preencoded_ber[WANDDER_PREENCODE_CSEQUENCE_0]);
        wandder_append_preencoded_ber(enc_ber, preencoded_ber[WANDDER_PREENCODE_OPERATORID]);
        wandder_append_preencoded_ber(enc_ber, preencoded_ber[WANDDER_PREENCODE_NETWORKELEMID]);
        wandder_encode_endseq_ber(enc_ber, 1);

        ptrdiff_t cin_diff = enc_ber->ptr - enc_ber->buf;
        wandder_encode_next_ber(enc_ber, WANDDER_TAG_INTEGER,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 1, &(cin),
                sizeof cin);

        wandder_append_preencoded_ber(enc_ber, preencoded_ber[WANDDER_PREENCODE_DELIVCC]);
        wandder_encode_endseq_ber(enc_ber, 1);

        ptrdiff_t seqno_diff = enc_ber->ptr - enc_ber->buf;
        wandder_encode_next_ber(enc_ber, WANDDER_TAG_INTEGER,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 4, &(seqno),
                sizeof seqno);

        if (preencoded_ber[WANDDER_PREENCODE_INTPOINTID]) {
            wandder_append_preencoded_ber(enc_ber, preencoded_ber[WANDDER_PREENCODE_INTPOINTID]);
            wandder_append_preencoded_ber(enc_ber, preencoded_ber[WANDDER_PREENCODE_CSEQUENCE_7]);
        } else {
            wandder_append_preencoded_ber(enc_ber, preencoded_ber[WANDDER_PREENCODE_CSEQUENCE_7]);
        }
        ptrdiff_t sec_diff = enc_ber->ptr - enc_ber->buf;
        wandder_encode_next_ber(enc_ber, WANDDER_TAG_INTEGER,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 0, &(tv->tv_sec),
                sizeof tv->tv_sec);

        ptrdiff_t usec_diff = enc_ber->ptr - enc_ber->buf;
        wandder_encode_next_ber(enc_ber, WANDDER_TAG_INTEGER,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 1, &(tv->tv_usec),
                sizeof tv->tv_usec);
        wandder_encode_endseq_ber(enc_ber, 1);
        wandder_append_preencoded_ber(enc_ber, preencoded_ber[WANDDER_PREENCODE_TVCLASS]);
        wandder_encode_endseq_ber(enc_ber, 1);
        wandder_append_preencoded_ber(enc_ber, preencoded_ber[WANDDER_PREENCODE_CSEQUENCE_2]);
        wandder_append_preencoded_ber(enc_ber, preencoded_ber[WANDDER_PREENCODE_CSEQUENCE_1]);
        wandder_append_preencoded_ber(enc_ber, preencoded_ber[WANDDER_PREENCODE_USEQUENCE]);

        ptrdiff_t dir_diff = enc_ber->ptr - enc_ber->buf;
        if (dir == 0) {
            wandder_append_preencoded_ber(enc_ber, preencoded_ber[WANDDER_PREENCODE_DIRFROM]);
        } else if (dir == 1) {
            wandder_append_preencoded_ber(enc_ber, preencoded_ber[WANDDER_PREENCODE_DIRTO]);
        } else if (dir == 2) {
            wandder_append_preencoded_ber(enc_ber, preencoded_ber[WANDDER_PREENCODE_DIRUNKNOWN]);
        } else {
            wandder_encode_next_ber(enc_ber, WANDDER_TAG_ENUM,
                    WANDDER_CLASS_CONTEXT_PRIMITIVE, 0, &dir,
                    sizeof dir);
        }

        wandder_append_preencoded_ber(enc_ber, preencoded_ber[WANDDER_PREENCODE_CSEQUENCE_2]);
        wandder_append_preencoded_ber(enc_ber, preencoded_ber[WANDDER_PREENCODE_CSEQUENCE_2]);
        wandder_append_preencoded_ber(enc_ber, preencoded_ber[WANDDER_PREENCODE_IPCCOID]);
        wandder_append_preencoded_ber(enc_ber, preencoded_ber[WANDDER_PREENCODE_CSEQUENCE_1]);

        ptrdiff_t ipcontent_diff = enc_ber->ptr - enc_ber->buf;
        wandder_encode_next_ber(enc_ber, WANDDER_TAG_IPPACKET,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 0, ipcontents, iplen);

        wandder_encode_endseq_ber(enc_ber, 7);

        res_ber = wandder_encode_finish_ber(enc_ber);
        

        //realign ptrs
        //ptrdiff_t offset = res_ber->buf - enc_ber->buf;

        top->buf                    = res_ber->buf;
        top->header.cin             = res_ber->buf + cin_diff;
        top->header.seqno           = res_ber->buf + seqno_diff;
        top->header.sec             = res_ber->buf + sec_diff;
        top->header.usec            = res_ber->buf + usec_diff;
        top->body.ipcc.dir          = res_ber->buf + dir_diff;
        top->body.ipcc.ipcontent    = res_ber->buf + ipcontent_diff;
        top->alloc_len = res_ber->len;
        top->len = res_ber->len;

        wandder_free_encoder_ber(enc_ber);
        free(res_ber);

    }
}


int main(int argc, char *argv[])
{
    runtimes = strtod(argv[1],NULL);

    wandder_etsili_intercept_details_t details;
    details.liid           = "liid"; 
    details.authcc         = "authcc";
    details.delivcc        = "delivcc";
    details.intpointid     = "intpointid";
    details.operatorid     = "operatorid";
    details.networkelemid  = "networkelemid";

    wandder_buf_t **preencoded_ber = calloc(WANDDER_PREENCODE_LAST, sizeof preencoded_ber);

    if (runtimes != 0){
        printf("prencoding..........");
        wandder_etsili_clear_preencoded_fields_ber(preencoded_ber);
        TIMEFUNC(
                {   //function to time
                    wandder_etsili_preencode_static_fields_ber(preencoded_ber, &details);
                },
                {   //reset code
                    wandder_etsili_clear_preencoded_fields_ber(preencoded_ber);
                }, 
                runtimes)
        printf("Needs to be done once per stream\n");
    }
    wandder_etsili_preencode_static_fields_ber(preencoded_ber, &details);

    // wandder_free_encoder_ber(enc_ber);    
    // //PRINTBUF(res_ber->buf, res_ber->len);
    // wandder_free_encoded_result_ber(res_ber);

    // free(item_buf->buf);
    // free(item_buf);

    printf("\nRunning ipcc tests.....\n");
    wandder_buf_t true_ipcc_buf = {true_ipcc, sizeof true_ipcc};
    test_encoding(&wandder_encode_etsi_ipcc_ber, preencoded_ber, true_ipcc_buf);

    printf("\nRunning ipmmcc tests...\n");
    wandder_buf_t true_ipmmcc_buf = {true_ipmmcc, sizeof true_ipmmcc};
    test_encoding(&wandder_encode_etsi_ipmmcc_ber, preencoded_ber, true_ipmmcc_buf);

    printf("\nRunning new method tests.....\n");
    test_encoding(&new_metho_ipcc, preencoded_ber, true_ipcc_buf);



    // printf("\nRunning ipmmiri tests...\n");
    // wandder_buf_t true_ipmmiri_buf = {true_ipmmiri, sizeof true_ipmmiri};
    // test_encoding(&wandder_encode_etsi_ipmmiri_ber, preencoded_ber, true_ipmmiri_buf);

    // printf("Running ipiri tests...\n");
    // wandder_buf_t true_ipiri_buf = {true_ipiri, sizeof true_ipiri};
    // test_encoding(&wandder_encode_etsi_ipiri_ber, preencoded_ber, true_ipiri_buf);


    wandder_etsili_clear_preencoded_fields_ber(preencoded_ber);
    free(preencoded_ber);

    return 0;
}