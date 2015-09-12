// Copyright (c) Athena Dev Teams - Licensed under GNU GPL
// For more information, see LICENCE in the main folder

#ifndef LOGIN_LOGINLOG_H
#define LOGIN_LOGINLOG_H

#include "../common/cbasetypes.h"
#include "account.h"
#include "login.h"

#ifdef HERCULES_CORE
// TODO: Interface
unsigned long loginlog_failedattempts(uint32 ip, unsigned int minutes);
void login_log(struct login_session_data* sd, uint32 ip, const char* username, int rcode, const char* message);
void ragna_login_log(struct login_session_data* sd, const char* ip, const char* username, int rcode, const char* message);
void ragna_login_log_acc(struct mmo_account* acc, const char* ip, const char* username, int rcode, const char* message);
bool loginlog_init(void);
bool loginlog_final(void);
bool loginlog_config_read(const char* w1, const char* w2);
#endif // HERCULES_CORE

#endif /* LOGIN_LOGINLOG_H */
