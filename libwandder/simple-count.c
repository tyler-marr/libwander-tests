

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>
#include <sys/socket.h>

#include <libwandder.h>
#include <libwandder_etsili.h>

#define PRINTBUF(ptr,len) for (size_t uniuqevari = 0; uniuqevari< len; uniuqevari++)\
            printf("%02x ",*(uint8_t *)(ptr+uniuqevari));

#define TIMEFUNC(func, reset, num) {                                                        \
    struct timespec start, end;                                                             \
    uint64_t delta_us = 0;                                                                  \
    uint64_t samples = 0;                                                                   \
    uint64_t total = 0;                                                                     \
    for (int uniuqevari = 0; uniuqevari < num; uniuqevari++){                               \
        clock_gettime(CLOCK_MONOTONIC, &start);                                             \
        func                                                                                \
       clock_gettime(CLOCK_MONOTONIC, &end);                                                \
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
                    0x81, 0x82, 0x00, 0x05, 0x00, 0xfe, 0xed, 0xbe, 0xef, 
                    0x82, 0x07, 0x64, 0x65, 0x6c, 0x69, 0x76, 0x63, 0x63, 
                0x00, 0x00, 
                0x84, 0x84, 0x00, 0x00, 0x00, 0x03, 0x00, 0xde, 0xad,
                0x86, 0x0a, 0x69, 0x6e, 0x74, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x69, 0x64,
                0xa7, 0x80,
                    0x80, 0x83, 0x00, 0x00, 0x04, 0x0b, 0xad, 0xca, 0xfe, 
                    0x81, 0x85, 0x00, 0x00, 0x00, 0x00, 0x02, 0x13, 0x37, 
                0x00, 0x00,
                0x88, 0x86, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01,
            0x00, 0x00};

uint8_t true_ipcc[] = {
            0xa2, 0x80, 
                0xa1, 0x80,
                    0x30, 0x80,
                        0x80, 0x86, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x42, 
                        0xa2, 0x80, 
                            0xa2, 0x80, 
                                0x80, 0x04, 0x05, 0x03, 0x0a, 0x02,
                                0xa1, 0x80, 
                                    0x80, 0x27, 
                                                0x74, 0x68, 0x69, 0x73,  0x20, 0x69, 0x73, 0x20,
                                                0x74, 0x68, 0x65, 0x20,  0x69, 0x70, 0x70, 0x63,
                                                0x20, 0x62, 0x6f, 0x64,  0x79, 0x20, 0x6f, 0x72,
                                                0x20, 0x74, 0x68, 0x65,  0x20, 0x69, 0x70, 0x63,
                                                0x6f, 0x6e, 0x74, 0x65,  0x6e, 0x74, 0x73,
                                0x00, 0x00, 
                            0x00, 0x00, 
                        0x00, 0x00, 
                    0x00, 0x00, 
                0x00, 0x00, 
            0x00, 0x00, 
        0x00, 0x00}; 

uint8_t true_ipmmcc[] = {
            0xa2, 0x80, 
                0xa1, 0x80,
                    0x30, 0x80,
                        0x80, 0x86, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x42, 
                        0xa2, 0x80, 
                            0xac, 0x80,
                                0x80, 0x04, 0x05, 0x05, 0x06, 0x02,
                                0x81, 0x27, 
                                            0x74, 0x68, 0x69, 0x73,  0x20, 0x69, 0x73, 0x20,
                                            0x74, 0x68, 0x65, 0x20,  0x69, 0x70, 0x70, 0x63,
                                            0x20, 0x62, 0x6f, 0x64,  0x79, 0x20, 0x6f, 0x72,
                                            0x20, 0x74, 0x68, 0x65,  0x20, 0x69, 0x70, 0x63,
                                            0x6f, 0x6e, 0x74, 0x65,  0x6e, 0x74, 0x73,
                                0x82, 0x86, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
                                0x82, 0x86, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
                            0x00, 0x00, 
                        0x00, 0x00, 
                    0x00, 0x00, 
                0x00, 0x00, 
            0x00, 0x00, 
        0x00, 0x00}; 

uint8_t true_ipmmiri[] = {
            0xa2, 0x80, 
                0xa0, 0x80,
                    0x30, 0x80,
                        0x80, 0x86, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x07,
                        0xa2, 0x80,
                        0xab, 0x80,
                            0x80, 0x04, 0x05, 0x05, 0x06, 0x01,
                            0xa1, 0x80,
                                0xa1, 0x80,
                                    0xa0, 0x80,
                                        0x81, 0x86, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
                                        0xa2, 0x80,
                                            0x81, 0x04, 0x01, 0x01, 0x01, 0x01,
                                        0x00, 0x00,
                                        0x83, 0x86, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03,
                                        0x85, 0x04, 0xff, 0xff, 0x00, 0x00,
                                    0x00, 0x00,
                                    0xa1, 0x80,
                                        0x81, 0x86, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
                                        0xa2, 0x80,
                                            0x81, 0x04, 0x02, 0x02, 0x02, 0x02,
                                        0x00, 0x00,
                                        0x83, 0x86, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03,
                                        0x85, 0x04, 0xff, 0xff, 0x00, 0x00,
                                    0x00, 0x00,
                                    0x82, 0x27, 
                                        0x74, 0x68, 0x69, 0x73,  0x20, 0x69, 0x73, 0x20,
                                        0x74, 0x68, 0x65, 0x20,  0x69, 0x70, 0x70, 0x63,
                                        0x20, 0x62, 0x6f, 0x64,  0x79, 0x20, 0x6f, 0x72,
                                        0x20, 0x74, 0x68, 0x65,  0x20, 0x69, 0x70, 0x63,
                                        0x6f, 0x6e, 0x74, 0x65,  0x6e, 0x74, 0x73, 
                                0x00, 0x00,
                            0x00, 0x00,
                        0x00, 0x00,
                    0x00, 0x00,
                0x00, 0x00,
            0x00, 0x00,
        0x00, 0x00,
    0x00, 0x00};

uint8_t true_ipiri[] = {
            0xa2, 0x80, 
                0xa0, 0x80,
                    0x30, 0x80,
                        0x80, 0x86, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x07,
                        0xa2, 0x80,
                        0xab, 0x80,
                            0x80, 0x04, 0x05, 0x05, 0x06, 0x01,
                            0xa1, 0x80,
                                0xa1, 0x80,
                                    0xa0, 0x80,
                                        0x81, 0x86, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
                                        0xa2, 0x80,
                                            0x81, 0x04, 0x01, 0x01, 0x01, 0x01,
                                        0x00, 0x00,
                                        0x83, 0x86, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03,
                                        0x85, 0x04, 0xff, 0xff, 0x00, 0x00,
                                    0x00, 0x00,
                                    0xa1, 0x80,
                                        0x81, 0x86, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
                                        0xa2, 0x80,
                                            0x81, 0x04, 0x02, 0x02, 0x02, 0x02,
                                        0x00, 0x00,
                                        0x83, 0x86, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03,
                                        0x85, 0x04, 0xff, 0xff, 0x00, 0x00,
                                    0x00, 0x00,
                                    0x82, 0x27, 
                                        0x74, 0x68, 0x69, 0x73,  0x20, 0x69, 0x73, 0x20,
                                        0x74, 0x68, 0x65, 0x20,  0x69, 0x70, 0x70, 0x63,
                                        0x20, 0x62, 0x6f, 0x64,  0x79, 0x20, 0x6f, 0x72,
                                        0x20, 0x74, 0x68, 0x65,  0x20, 0x69, 0x70, 0x63,
                                        0x6f, 0x6e, 0x74, 0x65,  0x6e, 0x74, 0x73, 
                                0x00, 0x00,
                            0x00, 0x00,
                        0x00, 0x00,
                    0x00, 0x00,
                0x00, 0x00,
            0x00, 0x00,
        0x00, 0x00,
    0x00, 0x00};

enum {
    IPCC,
    IPMMCC,
    IPIRI,
    IPMMIRI,
    NEWIPCC
};

void new_metho_ipcc(wandder_buf_t** preencoded_ber, int64_t cin, int64_t seqno,
        struct timeval* tv, void* ipcontents, size_t iplen, uint8_t dir,
        wandder_etsili_top_t* top);

#define ENCODE switch (testNum){\
        case IPCC:\
            wandder_encode_etsi_ipcc_ber(preencoded_ber, cin, seqno, &tv, ipcontents, iplen, dir, &top);\
        break;\
        case IPMMCC:\
            wandder_encode_etsi_ipmmcc_ber(preencoded_ber, cin, seqno, &tv, ipcontents, iplen, dir, &top);\
        break;\
        case IPIRI:\
            wandder_encode_etsi_ipiri_ber(preencoded_ber, cin, seqno, &tv, params, iritype, &top);\
        break;\
        case IPMMIRI:\
            wandder_encode_etsi_ipmmiri_ber(preencoded_ber, cin, seqno, &tv, ipcontents, iplen, iritype,\
            ipsrc, ipdest, ipfamily, &top);\
        break;\
        case NEWIPCC:\
            new_metho_ipcc(preencoded_ber, cin, seqno, &tv, ipcontents, iplen, dir,\
            &top);\
        break;\
    }

typedef struct test_values {
    uint32_t dec_cin;
    struct timeval testtv;
    int64_t seqno;
    uint8_t *cchdr;
    int64_t cclen;
} test_values_t;


int compare_test(wandder_etsili_top_t* top, test_values_t* test_values){
    wandder_etsispec_t* etsi_dec = wandder_create_etsili_decoder();
    wandder_attach_etsili_buffer(etsi_dec, top->buf, top->len, false);

    if (wandder_etsili_is_keepalive(etsi_dec)) {
            wandder_free_etsili_decoder(etsi_dec);
            printf("is keep alive\n");
    }

    uint32_t dec_cin = wandder_etsili_get_cin(etsi_dec);
    if (dec_cin != test_values->dec_cin){
        printf("DOES NOT MATCH\n");
        printf("cin \t%X %X\n", dec_cin, test_values->dec_cin);
        wandder_free_etsili_decoder(etsi_dec);
        return -1;
    }

    struct timeval testtv = wandder_etsili_get_header_timestamp(etsi_dec);
    if (testtv.tv_sec  != test_values->testtv.tv_sec ||
            testtv.tv_usec != test_values->testtv.tv_usec){
        printf("DOES NOT MATCH\n");
        printf("tv \t0x%lX.0x%lX, 0x%lX.0x%lX\n", 
                testtv.tv_sec, testtv.tv_usec,
                test_values->testtv.tv_sec, test_values->testtv.tv_usec);
        wandder_free_etsili_decoder(etsi_dec);
        return -1;
    } 
    
    wandder_reset_decoder(etsi_dec->dec);

    int64_t seqnoesti = wandder_etsili_get_sequence_number(etsi_dec);
    if ( seqnoesti != test_values->seqno ) {
        printf("DOES NOT MATCH\n");
        printf("seqno \t0x%lX\n", seqnoesti);
        wandder_free_etsili_decoder(etsi_dec);
        return -1;
    } 



    uint32_t cchdr_len;
    char namesp[1024];
    uint8_t *cchdr = wandder_etsili_get_cc_contents(etsi_dec, &cchdr_len, namesp, 1024);

   
    int passed = 0;
   
    if ( cchdr ) {
        if (memcmp((char *)cchdr, (char *)test_values->cchdr, test_values->cclen) != 0){
            printf("CC DOES NOT MATCH\n");
            printf("'");
            PRINTBUF(cchdr, cchdr_len);
            printf("', %d\n'", cchdr_len);
            PRINTBUF(test_values->cchdr, test_values->cclen);
            printf("', %ld\n", test_values->cclen);
            wandder_free_etsili_decoder(etsi_dec);
            return -1;
        }
        passed ^= 1;
    } else {
        wandder_reset_decoder(etsi_dec->dec);
        uint8_t ident;
        uint32_t iri_len;
        uint8_t *iricontents = wandder_etsili_get_iri_contents(etsi_dec, &iri_len, &ident, namesp, 1024);

        if ( iricontents ) {
            if (memcmp((char *)iricontents, (char *)test_values->cchdr, test_values->cclen) != 0){
                printf("IRI DOES NOT MATCH\n");
                printf("'");
                PRINTBUF(iricontents, iri_len);
                printf("', %d\n'", iri_len);
                PRINTBUF(test_values->cchdr, test_values->cclen);
                printf("', %ld\n", test_values->cclen);
                wandder_free_etsili_decoder(etsi_dec);
                return -1;
            }
            passed ^= 1;
        }
    }

    if (!passed) {
        printf("either both or neither passed (iri, ip)\n");
        wandder_free_etsili_decoder(etsi_dec);
        return -1;
    }

    wandder_free_etsili_decoder(etsi_dec);
    return 1;
}

int runtimes = 0;
void test_encoding(int testNum, wandder_buf_t **preencoded_ber, 
        wandder_buf_t true_body){

    int64_t cin = 0xfeedbeef;
    int64_t seqno = 0xdead;
    struct timeval tv;
    tv.tv_sec = 0xBADCAFE;
    tv.tv_usec = 0x1337;
    void * params = NULL;
    char* ipcontentsstring = "this is the ippc body or the ipcontents";
    size_t iplen = strlen(ipcontentsstring);
    uint8_t ipcontents[1000] = {3};
    memcpy(ipcontents, ipcontentsstring, iplen);
    uint8_t dir = 0x42; 
    uint8_t iritype = 0x7;

    uint32_t source_ip = 0x01010101;
    uint32_t dest_ip = 0x02020202;
    uint8_t *ipsrc = (uint8_t*)&source_ip;
    uint8_t *ipdest = (uint8_t*)&dest_ip;
    int ipfamily = AF_INET;

    test_values_t test_values = {
        cin,
        tv,
        seqno,
        ipcontents,
        iplen
    };

    wandder_etsili_top_t top;
    memset(&top, 0, sizeof top);
    
    ENCODE

    for (size_t i = 0; i < sizeof true_header; i++){
        uint8_t trueval =  *(uint8_t*)(true_header+i);
        uint8_t actualval = *(top.buf + i);
        //if (true_header[i] != *(uint8_t *)(top.buf+i)){
        if (trueval != actualval){
            PRINTBUF(top.buf, sizeof true_header)
            printf("\nelemetn %ld in header differs, true[0x%02x], actual[0x%02x]\n", i, trueval, actualval);
            PRINTBUF(true_header, sizeof true_header)
            printf("\n");
            assert(0);
        }
    }
    printf("header test done\n");

    ptrdiff_t bodylen = top.body.ipcc.ipcontent - (top.buf + sizeof true_header);

    for (size_t i = 0; i < true_body.len; i++){
        uint8_t trueval =  *(uint8_t*)((true_body.buf)+i);
        uint8_t actualval = *((top.buf + sizeof true_header)+i);
        if (trueval != actualval){
            printf("elemetn %ld in body differs, true[0x%02x], actual[0x%02x], bodylen = %ld\n", i, trueval, actualval, bodylen);
            PRINTBUF(top.buf + sizeof true_header, top.len - sizeof true_header)
            printf("\n");
            PRINTBUF(true_body.buf, true_body.len);
            printf("\n");
            assert(0);
        }
    }
    if (true_body.len + sizeof true_header != top.len){
        printf("true size = %4ld, actual size = %4ld\n", true_body.len + sizeof true_header, top.len);
        PRINTBUF(top.buf, top.len)
        printf("\n");
        assert(0);
    }
    printf("Passed test.\n");

    //test decoder 

    if ( compare_test(&top, &test_values) == -1) {
        printf("failed\n");
        assert(0);
    }

    //PRINTBUF(etsi_dec->dec->source, etsi_dec->dec->sourcelen)

    free(top.buf);
    memset(&top, 0, sizeof top);

    
    if (runtimes != 0){

        printf("encoding firsttime..\n");
        TIMEFUNC(
            {   //function to time
                ENCODE
            },
            {   
                if ( compare_test(&top, &test_values) == -1) {
                    printf("failed\n");
                    return;
                }
                //reset code
                free(top.buf);
                memset(&top, 0, sizeof top);
                cin = rand() >> (rand() % 64);
                seqno = rand() >> (rand() % 64);
                iplen = rand() % 1000;
                dir = rand() % 3;
                gettimeofday(&tv, NULL);
                test_values.dec_cin = cin;
                tv.tv_sec = 0;
                tv.tv_usec = 0;
                test_values.testtv.tv_sec  = tv.tv_sec;
                test_values.testtv.tv_usec  = tv.tv_usec;
                test_values.seqno   = seqno;
                test_values.cchdr   = ipcontents;
                test_values.cclen   = iplen; 
            }, 
            runtimes)
        printf("Needs to be done once per stream\n");

        gettimeofday(&tv, NULL);
        ENCODE
        // free(top.buf);
        // memset(&top, 0, sizeof top);
        cin = rand() >> (rand() % 64);
        seqno = rand() >> (rand() % 64);
        iplen = rand() % 1000;
        dir = rand() %3;
        gettimeofday(&tv, NULL);
        test_values.dec_cin = cin;
        test_values.testtv.tv_sec  = tv.tv_sec;
        test_values.testtv.tv_usec  = tv.tv_usec;
        test_values.seqno   = seqno;
        test_values.cchdr   = ipcontents;
        test_values.cclen   = iplen; 

        printf("update encoding.....");
        TIMEFUNC(
            {   //function to time
                ENCODE
            },
            {   //reset code
                if ( compare_test(&top, &test_values) == -1) {
                    printf("failed\n");
                    return;
                }
                cin = rand() >> (rand() % 64);
                seqno = rand() >> (rand() % 64);
                iplen = rand() % 1000;
                dir = rand() %3;
                gettimeofday(&tv, NULL);
                test_values.dec_cin = cin;
                test_values.testtv.tv_sec  = tv.tv_sec;
                test_values.testtv.tv_usec  = tv.tv_usec;
                test_values.seqno   = seqno;
                test_values.cchdr   = ipcontents;
                test_values.cclen   = iplen; 
            }, 
            runtimes)
        printf("Needs to be done everytime\n");
        free(top.buf);
        memset(&top, 0, sizeof top);
    }
}

typedef struct estili_pshdr_diff {
    
    ptrdiff_t cin_diff;
    ptrdiff_t seqno_diff;
    ptrdiff_t sec_diff;
    ptrdiff_t usec_diff;
}   estili_pshdr_diff_t;

void new_etsili_pshdr_pc(wandder_encoder_ber_t* enc_ber, 
        wandder_buf_t** preencoded_ber, int64_t cin, int64_t seqno,
        struct timeval* tv, wandder_etsili_top_t* top, 
        estili_pshdr_diff_t* pshdr_diff) {

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

        pshdr_diff->cin_diff = enc_ber->ptr - enc_ber->buf;
        wandder_encode_next_ber(enc_ber, WANDDER_TAG_INTEGER,
        WANDDER_CLASS_CONTEXT_PRIMITIVE, 1, &(cin),
        sizeof cin);

        wandder_append_preencoded_ber(enc_ber, preencoded_ber[WANDDER_PREENCODE_DELIVCC]);
        wandder_encode_endseq_ber(enc_ber, 1);

        pshdr_diff->seqno_diff = enc_ber->ptr - enc_ber->buf;
        wandder_encode_next_ber(enc_ber, WANDDER_TAG_INTEGER,
        WANDDER_CLASS_CONTEXT_PRIMITIVE, 4, &(seqno),
        sizeof seqno);

        if (preencoded_ber[WANDDER_PREENCODE_INTPOINTID]) {
            wandder_append_preencoded_ber(enc_ber, preencoded_ber[WANDDER_PREENCODE_INTPOINTID]);
        }
        wandder_append_preencoded_ber(enc_ber, preencoded_ber[WANDDER_PREENCODE_CSEQUENCE_7]);


        pshdr_diff->sec_diff = enc_ber->ptr - enc_ber->buf;
        wandder_encode_next_ber(enc_ber, WANDDER_TAG_INTEGER,
        WANDDER_CLASS_CONTEXT_PRIMITIVE, 0, &(tv->tv_sec),
        sizeof tv->tv_sec);

        pshdr_diff->usec_diff = enc_ber->ptr - enc_ber->buf;
        wandder_encode_next_ber(enc_ber, WANDDER_TAG_INTEGER,
        WANDDER_CLASS_CONTEXT_PRIMITIVE, 1, &(tv->tv_usec),
        sizeof tv->tv_usec);

        wandder_encode_endseq_ber(enc_ber, 1);

        wandder_append_preencoded_ber(enc_ber, preencoded_ber[WANDDER_PREENCODE_TVCLASS]);
        wandder_encode_endseq_ber(enc_ber, 1);
}

void update_etsili_pshdr_pc(wandder_etsili_top_t* top, int64_t cin,
        int64_t seqno, struct timeval* tv){
    

    ber_rebuild_integer(
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            1, 
            &(cin), 
            sizeof cin,
            top->header.cin);

    ber_rebuild_integer(
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            4, 
            &(seqno), 
            sizeof seqno,
            top->header.seqno);

    ber_rebuild_integer(
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            0, 
            &(tv->tv_sec), 
            sizeof tv->tv_sec,
            top->header.sec);

    ber_rebuild_integer(
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 
            1, 
            &(tv->tv_usec), 
            sizeof tv->tv_usec,
            top->header.usec);
}

void new_metho_ipcc(wandder_buf_t** preencoded_ber, int64_t cin, int64_t seqno,
        struct timeval* tv, void* ipcontents, size_t iplen, uint8_t dir,
        wandder_etsili_top_t* top){

    wandder_encoded_result_ber_t* res_ber;
    estili_pshdr_diff_t pshdr_diff;

        

    if (top->buf){
        update_etsili_pshdr_pc(top, cin, seqno, tv);

        if (dir == 0) {
            memcpy(top->body.ipcc.dir, 
                    preencoded_ber[WANDDER_PREENCODE_DIRFROM]->buf, 
                    preencoded_ber[WANDDER_PREENCODE_DIRFROM]->len);
        } else if (dir == 1) {
            memcpy(top->body.ipcc.dir, 
                    preencoded_ber[WANDDER_PREENCODE_DIRTO]->buf, 
                    preencoded_ber[WANDDER_PREENCODE_DIRTO]->len);
        } else if (dir == 2) {
            memcpy(top->body.ipcc.dir, 
                    preencoded_ber[WANDDER_PREENCODE_DIRUNKNOWN]->buf, 
                    preencoded_ber[WANDDER_PREENCODE_DIRUNKNOWN]->len);
        } else {
            ber_rebuild_integer(
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 
                0, 
                &(dir), 
                sizeof dir,
                top->body.ipcc.dir);
        }
        uint8_t * ptr = top->body.ipcc.ipcontent;
        ptr += wandder_encode_inplace_ber(WANDDER_CLASS_CONTEXT_PRIMITIVE, 
                0,
                WANDDER_TAG_IPPACKET,
                ipcontents, 
                iplen,
                top->body.ipcc.ipcontent,
                top->alloc_len - (ptr - top->buf));

        ENDCONSTRUCTEDBLOCK(ptr,7) //endseq
        
    } else {

        wandder_encoder_ber_t* enc_ber = wandder_init_encoder_ber(5000, 0);
        
        new_etsili_pshdr_pc(enc_ber, preencoded_ber, cin, seqno, tv, top, &pshdr_diff);

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

        top->buf                    = res_ber->buf;
        top->header.cin             = res_ber->buf + pshdr_diff.cin_diff;
        top->header.seqno           = res_ber->buf + pshdr_diff.seqno_diff;
        top->header.sec             = res_ber->buf + pshdr_diff.sec_diff;
        top->header.usec            = res_ber->buf + pshdr_diff.usec_diff;
        top->body.ipcc.dir          = res_ber->buf + dir_diff;
        top->body.ipcc.ipcontent    = res_ber->buf + ipcontent_diff;
        top->len                    = res_ber->len;

        wandder_free_encoder_ber(enc_ber);
        free(res_ber);
    }
}

int main(int argc, char *argv[])
{
    if (argc != 2){
        printf("usage: %s [runtimes]\n", argv[0]);
        return 0;
    }
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



    wandder_buf_t true_ipcc_buf = {true_ipcc, sizeof true_ipcc};
    printf("\nRunning new ipcc method tests.....\n");
    test_encoding(NEWIPCC, preencoded_ber, true_ipcc_buf);

    printf("\nRunning ipcc tests.....\n");
    test_encoding(IPCC, preencoded_ber, true_ipcc_buf);    

    wandder_buf_t true_ipmmcc_buf = {true_ipmmcc, sizeof true_ipmmcc};
    printf("\nRunning ipmmcc tests...\n");    
    test_encoding(IPMMCC, preencoded_ber, true_ipmmcc_buf);

    wandder_buf_t true_ipmmiri_buf = {true_ipmmiri, sizeof true_ipmmiri};
    printf("\nRunning ipmmiri tests...\n");
    test_encoding(IPMMIRI, preencoded_ber, true_ipmmiri_buf);

    // wandder_buf_t true_ipiri_buf = {true_ipiri, sizeof true_ipiri};
    // printf("\nRunning IPIRI tests...\n");
    // test_encoding(IPIRI, preencoded_ber, true_ipiri_buf);

    wandder_etsili_clear_preencoded_fields_ber(preencoded_ber);
    free(preencoded_ber);

    return 0;
}