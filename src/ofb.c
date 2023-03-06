/*
 *  File: bfish_ofb.c
 *  Author: Claes M. Nyberg <cmn@signedness.org>
 *  Description: Blowfish Output Feedback Mode routine.
 *  Version: 1.0
 *  Date: Tue Oct 22 05:59:41 CEST 2002
 *
 *  Copyright (c) 2002 Claes M. Nyberg <cmn@signedness.org>
 *  All rights reserved, all wrongs reversed.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. The name of author may not be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 *  INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 *  AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 *  THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 *  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 *  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 *  OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 *  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 *  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 *  ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <sys/types.h>
#include "bfish.h"

/*
 * Decrypt/encrypt a string of bytes using OFB mode.
 *
 * str   - The string of bytes.
 * slen  - The length of str in bytes.
 * iv    - The eight byte long initial vector.
 * bsize - The size of the subblock, 8, 16 or 32 bits.
 *         Note that the input array needs to be aligned to
 *         the number of bits used in the subblock.
 * bk    - The blowfish key initialized by bfish_keyinit()
 */
void
bfish_ofb(u_char *str, u_long slen, u_char *iv, 
					u_char bsize, struct bfish_key *bk)
{
	u_long bytes;
	int i;

	switch (bsize) {
		case 8:  break;
		case 16: break;
		case 32: break;
		default: 
			fprintf(stderr, "bfish_ofb(): Bad subblock size: %d. "
				"should be 8, 16 or 32 bits.\n", bsize);
			return;
			break;
	}
	
	bytes = (bsize/8);
	
	if (slen % bytes) {
		fprintf(stderr, "bfish_ofb(): Message is not aligned to "
			"%d bit boundary!\n", bsize);
		return;
	}

	while (slen >= bytes) {
		bfish_encrypt((u_long *)&iv[0], (u_long *)&iv[4], bk);
		
		for (i=0; i<bytes; i++) 
			*(str++) ^= iv[i];
		
		slen -= bytes;
	}
}
