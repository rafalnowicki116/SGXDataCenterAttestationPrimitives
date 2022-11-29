/*
Copyright (c) 2018 SafeNet. All rights reserved.

This file contains information that is proprietary to SafeNet and may not be
distributed or copied without written consent from SafeNet.
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <cryptoki.h>

#include "fm/hsm/fmsw.h"
#include "fm/hsm/fm.h"
#include "fm/common/fm_byteorder.h"

#include "../include/qvl.h"
//#include "library.h"
#include "QuoteVerification.h"


static void dispatch_message(FmMsgHandle token, void *req, uint32_t req_len)
{
   uint32_t len;
   uint32_t slot;
   char buf[TEXT_BUF_SIZE];
   char *rep;
   CK_SESSION_HANDLE session = 0;
   CK_RV rv;

   printf("Sasdadas");
   sgxAttestationGetVersion();   
   //hello();  
   /* this example simply echoes the data it received back to the host.
    * It also opens a session temporarily on the slot specified by the caller.
    *
    * First, we read the embedded slot number, which is encoded as big-endian
    */

   if (req_len < sizeof(slot)) {
      SVC_SendReply(token, FM_ERR_INVALID_LENGTH);
      return;
   }

   slot = fm_betoh32(*(uint32_t *)req);
   uint32_t *dupa = (uint32_t *)req;
   dupa += sizeof(uint32_t);
   req_len -= sizeof(uint32_t);

   /*
    * Next, we read the data size, which is encoded as big-endian
    */
   if (req_len < sizeof(len)) {
      SVC_SendReply(token, FM_ERR_INVALID_LENGTH);
      return;
   }

   len = fm_betoh32(*(uint32_t *)dupa);

   dupa += sizeof(uint32_t);
   req_len -= sizeof(uint32_t);

   /*
    * Ensure there is sufficent data left in the request message
    */
   if ((len > sizeof(buf) || (req_len != len))) {
      /* buffer which was passed in is too long for us to read */
      SVC_SendReply(token, FM_ERR_INVALID_LENGTH);
      return;
   }

   /* the remainder of the request contains the data we want to echo.  start by
    * copying the data to a local buffer */
   // memcpy(buf,req,len);

   /* get the reply buffer, specifying the size.  This cannot be more than
    * the sum total of the size of all reply buffers on the host. */
   if ((rep = (char*)SVC_GetReplyBuffer(token, sizeof(len)+len)) == NULL) {
      SVC_SendReply(token, FM_ERR_OUT_OF_MEMORY);
      return;
   }

   /* write the number of bytes we received, which we encode as big-endian */
   *(uint32_t*)rep=fm_htobe32(len);
   rep+=sizeof(uint32_t);

   /* copy our received data to the reply buffer */
   // memcpy(rep,buf,len);

   /*
    * Now open a session on the embedded slot - just to show we can
    */
   rv = C_OpenSession((CK_SLOT_ID)slot, CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL, NULL, &session);

   if (rv != CKR_OK) {
      SVC_SendReply(token, FM_UNSUCCESSFUL);
      return;
   }

   C_CloseSession(session);

   /* send the reply */
   SVC_SendReply(token, FM_OK);
   return;
}

FM_RV Startup(void)
{
   return (FM_RV)FMSW_RegisterRandomDispatch(GetFMID(), dispatch_message);
}