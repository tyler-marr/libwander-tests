#include "libtrace.h"
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include <libwandder.h>
#include <libwandder_etsili.h>

uint64_t pktcount = 0;
uint64_t bytecount = 0;

char *expectedliid;

libtrace_t *trace;
FILE *fout = NULL;

struct cintracker {
        uint32_t cin;
        int64_t nextseq;
};

struct cintracker knowncins[256];
int cinseen = 0;
int firsttime = 1;

static int per_packet(libtrace_packet_t *packet) {

	char *buf;
        int i;
	uint32_t rem;
        char namesp[1024];
        uint8_t *cchdr;
        uint8_t *iricontents;
        uint8_t ident;
        char liid[1024];
        int64_t seq;
        libtrace_linktype_t linktype;
        wandder_etsispec_t *dec = NULL;
        uint32_t cin;
        struct cintracker *ctrack = NULL;

	buf = trace_get_packet_buffer(packet, &linktype, &rem);
        if (buf == NULL || rem == 0) {
                return 0;
        }

        dec = wandder_create_etsili_decoder();
        wandder_attach_etsili_buffer(dec, (uint8_t *)buf, rem, false);

        if (wandder_etsili_is_keepalive(dec)) {
                wandder_free_etsili_decoder(dec);
                return 0;
        }

        cin = wandder_etsili_get_cin(dec);

        cchdr = wandder_etsili_get_cc_contents(dec, &rem, namesp, 1024);
        if (cchdr) {
                pktcount += 1;
                bytecount += rem;
        } else {
                iricontents = wandder_etsili_get_iri_contents(dec, &rem,
                                &ident, namesp, 1024);



                if (!iricontents) {
                        for(int i = 0; i< dec->dec->sourcelen; i++){
                                printf("%02x ", *(uint8_t*)(buf+i));
                        } exit(0);
                        wandder_free_etsili_decoder(dec);
                        printf("invalid iri and cc\n");
                        
                        return 0;
                }



                pktcount += 1;
                bytecount += rem;
        }

        if (wandder_etsili_get_liid(dec, liid, 1024) == NULL) {
                fprintf(fout, "error: could not extract LIID from ETSI record?\n");
                wandder_free_etsili_decoder(dec);
                return -1;
        }

        if (strcmp(liid, expectedliid) != 0) {
                fprintf(fout, "error: unexpected LIID in ETSI record (%s)\n",
                                liid);
                wandder_free_etsili_decoder(dec);
                return -1;
        }

        for (i = 0; i < cinseen; i++) {
                if (knowncins[i].cin == cin) {
                        ctrack = &(knowncins[i]);
                        break;
                }
        }

        if (ctrack == NULL) {
                knowncins[cinseen].cin = cin;
                knowncins[cinseen].nextseq = 0;
                ctrack = &(knowncins[cinseen]);
                cinseen ++;

                if (cinseen >= 256) {
                        fprintf(fout, "error: too many different CINs observed?\n");
                        wandder_free_etsili_decoder(dec);
                        return -1;
                }
        }

        seq = wandder_etsili_get_sequence_number(dec);
        if (seq != ctrack->nextseq) {
                for(int i = 0; i< rem; i++){
                        printf("%02x ", *(uint8_t*)(buf+i));
                }
                fprintf(fout, "error: unexpected sequence number for ETSI record (got %ld, wanted %ld -- cin=%u)\n", seq, ctrack->nextseq, cin);
                wandder_free_etsili_decoder(dec);
                return -1;
        }

        ctrack->nextseq = seq + 1;
        wandder_free_etsili_decoder(dec);
        return 1;
}

static void cleanup_signal(int signal) {
        trace_interrupt();
}

int main(int argc, char *argv[])
{
        libtrace_packet_t *packet;
        struct sigaction sigact;
        int pkterror = 0;

        if (argc<5) {
                fprintf(stderr,"usage: %s libtraceuri (expected pkts) (expected bytes) (expected LIID)\n",argv[0]);
                return 1;
        }

        sigact.sa_handler = cleanup_signal;
        sigemptyset(&sigact.sa_mask);
        sigact.sa_flags = SA_RESTART;

        sigaction(SIGINT, &sigact, NULL);
        sigaction(SIGTERM, &sigact, NULL);

        fout = fopen("/tmp/openli-test.out", "w");
        if (!fout) {
                return 1;
        }

        expectedliid = argv[4];
        trace = trace_create(argv[1]);

        if (trace_is_err(trace)) {
                trace_perror(trace,"Opening trace file");
                return 1;
        }

        if (trace_start(trace)) {
                trace_perror(trace,"Starting trace");
                trace_destroy(trace);
                return 1;
        }

        packet = trace_create_packet();

        while (trace_read_packet(trace,packet)>0) {
                if (per_packet(packet) < 0) {
                        printf("pkt err\n");
                        pkterror = 1;
                        break;
                }
                //printf("packet count %lu, byte count %lu\n", pktcount, bytecount);
        }

        if (pkterror == 0) {
                if (bytecount != strtoul(argv[3], NULL, 10)) {
                        fprintf(fout, "error: total bytes was %lu, expected %lu\n",
                                        bytecount, strtoul(argv[3], NULL, 10));
                        pkterror = 1;
                }

                if (pktcount != strtoul(argv[2], NULL, 10)) {
                        fprintf(fout, "error: total packets was %lu, expected %lu\n",
                                        pktcount, strtoul(argv[2], NULL, 10));
                        pkterror = 1;
                }
        }

        trace_destroy_packet(packet);

        if (trace_is_err(trace)) {
                trace_perror(trace,"Reading packets");
                trace_destroy(trace);
                return 1;
        }

        if (!pkterror) {
                fprintf(fout, "success\n");
        } else {
                fprintf(fout, "failed\n");
        }
        fclose(fout);
        trace_destroy(trace);
        return 0;
}

