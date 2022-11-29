/*
Copyright (c) 2018 SafeNet. All rights reserved.

This file contains information that is proprietary to SafeNet and may not be
distributed or copied without written consent from SafeNet.
*/

#include <vector>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>
#include <vector>

 extern "C" {
    #include <fm/common/fmerr.h>
    #include <fm/host/md.h>
    #include <fm/host/mdStrings.h>
    #include <fm/common/integers.h>
    #include <fm/common/fm_byteorder.h>
    #include "cryptoki.h"
    #include "qvl.h"
 }
const static char *myname;

 #ifdef WIN32
 #  include <windows.h>
 #define DIRSEP '\\'
 #else
 #  include <sys/time.h>
 #define DIRSEP '/'
 #endif


 static void set_myname (int argc, char *argv[])
 {
    if (argc < 1) {
       myname = "????";
    } else {
       char *last_slash = strrchr(argv[0], DIRSEP);
       if (last_slash)
          myname = last_slash + 1;
       else
          myname = argv[0];
    }
 }
 MD_RV SkeletonMDInitialize(
    int p11SlotNum,               // IN
    uint32_t *adapterNum,         // OUT
    CK_SLOT_ID *embeddedSlotNum,  // OUT
    char *fm_name,                // IN
    uint32_t *fmid)               // OUT
 {
    MD_RV rv;    
    rv = MD_Initialize();
    if (rv != MDR_OK) {
       fprintf(stderr,
          "Error: MD_Initialize failed with rv=0x%08x %s\n", rv, MD_RvAsString(rv));
       return rv;
    }

    /*
     * get the corresponding hsm device number from the p11 slot we specified
     */
    rv = MD_GetHsmIndexForSlot(p11SlotNum, adapterNum);

    if (rv != MDR_OK) {
       fprintf(stderr,
          "Error: could not get hsm index for slot %d\n"
          "   MD_GetEmbeddedSlotID returned 0x%08x %s\n",
          p11SlotNum, rv, MD_RvAsString(rv));
       MD_Finalize();
       return rv;
    }

    /*
     * get the corresponding slot number as seen from the perspective of the
     * hsm firmware
     */
    rv = MD_GetEmbeddedSlotID(p11SlotNum, embeddedSlotNum);

    if (rv != MDR_OK) {
       fprintf(stderr,
          "Error: could not get embedded slot id for slot %d\n"
          "   MD_GetEmbeddedSlotID returned 0x%08x %s\n",
          p11SlotNum, rv, MD_RvAsString(rv));
       MD_Finalize();
       return rv;
    }

    /* find the fm id for the fm named 'skeleton'.  The fmid is passed in to
     * MD_SendReceive to direct requests to the 'skeleton' fm on the HSM */
    rv = MD_GetFmIdFromName(*adapterNum, fm_name, (uint32_t)strlen(fm_name), fmid);

    if (rv != MDR_OK) {
       fprintf(stderr,
          "Error: could not get id for fm named %s\n"
          "   MD_GetFmIdFromName returned 0x%08x %s\n",
          fm_name, rv, MD_RvAsString(rv));

       MD_Finalize();
       return rv;
    }

    printf("p11 slot = %d, hsm device = %d, embedded slot = %d, fmid = 0x%04x\n",
       p11SlotNum, *adapterNum, (int)*embeddedSlotNum, *fmid);
    return rv;
 }

 MD_RV SkeletonDoCommand(
    uint32_t adapterNum,
    CK_SLOT_ID embeddedSlotNum,
    uint32_t fmid,
    char *pText)
 {
    MD_RV rv;
    MD_Buffer_t request[4];
    MD_Buffer_t response[3];
    uint32_t temp;
    uint32_t rsp_len;
    uint32_t txt_len;
    uint32_t recv_len;
    uint32_t fm_status;
    uint32_t slot;
    char buf[TEXT_BUF_SIZE];

    /*
     * Requests consist of an array of MD_Buffer_t structures, where each
     * structure consists of a pointer to data to send and a length.  The array
     * is terminated by a request buffer with both fields set to 0.
     *
     * The FM in this example does two things; it reads a string of text and
     * echos it back to the host; and it opens and closes a session on the
     * given slot. Our request has four buffers:
     *
     * request[0] is used to send a single 32-bit integer value which contains
     * embedded slot number corresponding to the p11 slot which was specified
     * with the '-s' parameter
     *
     * request[1] is used to send a single 32-bit integer value which contains
     * the number of bytes to data bytes to send
     *
     * request[2] is used for the actual data
     *
     * request[3] is the terminating null buffer.
     *
     * Responses similarly consist of an array of MD_Buffer_t structures,
     * terminated by a null buffer.
     *
     * In our example, the response buffers are as follows
     *
     * response[0] is used to receive a single 32-bit integer value which contains
     * the number of data bytes which the fm received
     *
     * response[1] is used to receive a copy of the data which was sent in the
     * request
     *
     * response[2] is the terminating null buffer.
     *
     * Note that by convention, integers are encoded as big-endian when being
     * transferred from host to fm or vice-versa.
     *
     * This example returns 'MDR_OK' if the data received by the FM exactly
     * matches the data we sent.
     */
    slot = fm_htobe32((uint32_t)embeddedSlotNum);
    request[0].pData = (uint8_t *)&slot;
    request[0].length = 4;

    txt_len = (uint32_t)strlen(pText);
    temp = fm_htobe32(txt_len);
    request[1].pData = (uint8_t *)&temp;
    request[1].length = 4;

    request[2].pData = (uint8_t *)pText;
    request[2].length = txt_len;

    request[3].pData = NULL;
    request[3].length = 0;

    rsp_len = 0;

    response[0].pData = (uint8_t *)&rsp_len;
    response[0].length = sizeof(rsp_len);

    response[1].pData = (uint8_t *)buf;
    response[1].length = txt_len;

    response[2].pData = NULL;
    response[2].length = 0;

    rv = MD_SendReceive(adapterNum, 0, (uint16_t)fmid, request, 10000, response, &recv_len, &fm_status);
    if (rv != MDR_OK || fm_status != FM_OK) {
       printf("FAILED with rv = %x (%s), fm_status = %u\n", rv, MD_RvAsString(rv), fm_status);
       return (rv)?rv:(MD_RV)fm_status;
    } else {
       rsp_len = fm_betoh32(*(uint32_t *)&rsp_len);

       if (rsp_len != txt_len) {
          printf("Received length %d does not match sent length %d\n", rsp_len, txt_len);
          return MDR_UNSUCCESSFUL;
       }

       if (memcmp(pText,buf,txt_len)) {
          printf("Received string %s does not match sent string %s\n", buf, pText);
          return MDR_UNSUCCESSFUL;
       }
    }
    return MDR_OK;
 }

 void usage(int err)
 {
     fprintf(stderr, "usage %s [-h] [-?] -s<slotnum> -t<text>\n", myname );
     fprintf(stderr, "\t-h : display usage and exit\n");
     fprintf(stderr, "\t-s<slotnum> : specify P11 slot number\n");
     fprintf(stderr, "\t-t<text> : text to echo\n");
     fprintf(stderr, "\n");
     fprintf(stderr, "\tSimple Sample FM : connect to FM associated with HSM with P11 <slotnum>\n");
     fprintf(stderr, "\tand send a message to that FM\n");
     fprintf(stderr, "\tExample : %s -s3 -t \"my message\"\n", myname);

     exit(err);
 }

int main(int argc, char * argv[])
{
    std::vector<int> dupa;

    MD_RV rv;
    int p11SlotNum = 0;
    bool bSlotSpecified = false;
    uint32_t adapterNum = 0;
    CK_SLOT_ID embeddedSlotNum = 0;
    uint32_t fmid;
    char *pArg = NULL;
    char *pVal = NULL;
    char *pText = NULL;

    printf("\nSample FM test program\n\n");
    std::vector<int> aaa;
    set_myname(argc, argv);

     if ( *argv != NULL ) {
         ++argv;
     }

    while( (pArg = *(argv++)) != NULL ) {

#define GETOPTVAL \
      (pArg[2] != '\0') ? pArg+2 : ((pArg=*(argv++)), pArg)


        if (pArg[0] == '-')
        {
          /* process command line options */
          switch( pArg[1] ) {
             case 'h':
             case '?':
                usage(EXIT_SUCCESS);
             case 's':
                bSlotSpecified = true;
                if ( (pVal = GETOPTVAL) == NULL )
                   usage(EXIT_FAILURE);
                p11SlotNum = atoi(pVal);
                break;
             case 't':
                if ( (pText = GETOPTVAL) == NULL )
                   usage(EXIT_FAILURE);
                break;
             default:
                usage(EXIT_FAILURE);
                break;
          }
      } else {
         usage(EXIT_FAILURE);
      }
    }

     if (! pText)
     {
        printf("Missing text to send\n");
        usage(EXIT_FAILURE);
     }

     if (! bSlotSpecified) {
        fprintf(stderr, "Error: must specify slot parameter\n");
        usage(EXIT_FAILURE);
     }

     rv = SkeletonMDInitialize(p11SlotNum, &adapterNum, &embeddedSlotNum,
                               (char*)SKELETON_FM_PRODUCT_ID, &fmid);

     if (rv != MDR_OK) {
        fprintf(stderr, "SkeletonMDInitialize failed rv=%0x\n", rv);
        return EXIT_FAILURE;
     }

     rv = SkeletonDoCommand(adapterNum, embeddedSlotNum, fmid, pText);

     if (rv == MDR_OK)
        printf("SUCCESS\n");

     MD_Finalize();
     return (rv)?EXIT_FAILURE:EXIT_SUCCESS;
}
