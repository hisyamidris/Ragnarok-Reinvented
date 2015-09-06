// Copyright (c) 2015 RagnaShield Project
// Conflicts / Nanakiwurtz / Tokeiburu
//
//  - E-mail: admin@ragnahosting.com
//  - Website: https://ragnahosting.com
//  - Facebook: https://facebook.com/ragnahosting
//  - Twitter: https://twitter.com/ragnahosting
//
// This file is NOT public - you are not allowed to distribute it.
// RagnaShield is a free GameGuard offered exclusively to RagnaHosting customers.



#ifndef LOGIN_RAGNABAN_H
#define LOGIN_RAGNABAN_H

#include "../common/cbasetypes.h"
#include "login.h"

#ifdef HERCULES_CORE
#define RS_PACKET_LENGTH 26

// TODO: Interface
// initialize
void ragnaban_init(void);

// finalize
void ragnaban_final(void);

// check the hardware IDs against ban list
bool ragnaban_check(struct login_session_data* sd);

// parses configuration option
bool ragnaban_config_read(const char *key, const char* value);
bool rs_validate_packet(int fd, int length);
bool rs_auth_check(struct login_session_data* sd, const char * ip, const char * username, int fd, int length);
bool rs_ban_check(struct login_session_data* sd, const char * ip, const char * username);
int ragna_config_read(const char* cfgName);

#endif // HERCULES_CORE

#endif /* LOGIN_RAGNABAN_H */
