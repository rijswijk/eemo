/*
 * Copyright (c) 2010-2015 SURFnet bv
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of SURFnet bv nor the names of its contributors 
 *    may be used to endorse or promote products derived from this 
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/*
 * The Extensible Ethernet Monitor Sensor Multiplexer(EEMO)
 * Multiplexer protocols
 */

#ifndef _EEMO_MUX_PROTO_H
#define _EEMO_MUX_PROTO_H

#include "config.h"

/* Feed to multiplexer protocol */
#define SENSOR_PROTO_VERSION			1
#define SENSOR_GET_PROTO_VERSION		0x01
#define SENSOR_REGISTER				0x02
#define SENSOR_SET_DESCRIPTION			0x03
#define SENSOR_UNREGISTER			0x04
#define SENSOR_SHUTDOWN				0x05
#define SENSOR_DATA				0x06

/* Client to multiplexer protocol */
#define MUX_CLIENT_PROTO_VERSION		2
#define MUX_CLIENT_GET_PROTO_VERSION		0x01
#define MUX_CLIENT_SUBSCRIBE			0x02
#define MUX_CLIENT_SHUTDOWN			0x04
#define MUX_CLIENT_DATA				0x05

#define MUX_SUBS_RES_NX				0
#define MUX_SUBS_RES_OK				1
#define MUX_SUBS_RES_ERR			2

#endif /* !_EEMO_MUX_PROTO_H */

