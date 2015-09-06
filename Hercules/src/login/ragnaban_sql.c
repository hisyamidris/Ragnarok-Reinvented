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


#define HERCULES_CORE
#define HW_BAN_SENSITIVITY_MIN 0
#define HW_BAN_SENSITIVITY_DEFAULT 2
#define HW_BAN_SENSITIVITY_MAX 3

#include "ragnaban.h"

#include <stdlib.h>
#include <string.h>

#include "login.h"
#include "loginlog.h"
#include "../common/cbasetypes.h"
#include "../common/db.h"
#include "../common/malloc.h"
#include "../common/sql.h"
#include "../common/socket.h"
#include "../common/strlib.h"
#include "../common/timer.h"
#include "../common/showmsg.h"

// global sql settings
static char   global_db_hostname[32] = "127.0.0.1";
static uint16 global_db_port = 3306;
static char   global_db_username[32] = "ragnarok";
static char   global_db_password[100] = "ragnarok";
static char   global_db_database[32] = "ragnarok";
static char   global_codepage[32] = "";
// local sql settings
static char   ragnaban_db_hostname[32] = "";
static uint16 ragnaban_db_port = 0;
static char   ragnaban_db_username[32] = "";
static char   ragnaban_db_password[100] = "";
static char   ragnaban_db_database[32] = "";
static char   ragnaban_codepage[32] = "";
static char   ragnaban_table[32] = "ragnashield_banlist";

// globals
static Sql* sql_handle = NULL;
static int cleanup_timer_id = INVALID_TIMER;
static bool ragnaban_inited = false;

static unsigned char RagnaShieldKey[256] = { 
	0xF6, 0x88, 0x01, 0x21, 0x12, 0x55, 0x33, 0x1D, 0x56, 0xEC, 0x31, 0x26, 0xC5, 0x36, 0xC3, 0x41,
	0x4A, 0x5F, 0x7D, 0x38, 0x0C, 0x61, 0x5E, 0x48, 0x11, 0xC0, 0xBC, 0xE9, 0x9B, 0x9F, 0x37, 0x52,
	0xB0, 0x2F, 0x10, 0x6A, 0x0B, 0x02, 0x7C, 0xFE, 0x99, 0xD3, 0x35, 0x98, 0x73, 0x15, 0x4F, 0x40,
	0x94, 0x8A, 0xA7, 0x17, 0x91, 0x3D, 0x8B, 0x20, 0xDF, 0xE3, 0x72, 0xEE, 0xBA, 0x85, 0xC1, 0x2D,
	0x63, 0x7F, 0x04, 0x45, 0x03, 0x54, 0x5A, 0x78, 0x18, 0x34, 0x29, 0x5D, 0xAC, 0xF4, 0x44, 0xEA,
	0xE0, 0x8D, 0x9C, 0xC6, 0xF3, 0x7B, 0x68, 0x3C, 0x08, 0xAE, 0x6B, 0xFA, 0x1A, 0x80, 0x75, 0x24,
	0x90, 0x00, 0x16, 0x0A, 0xC9, 0x6F, 0xDC, 0xDA, 0xCF, 0x82, 0xA3, 0xA1, 0xF7, 0xBF, 0xC2, 0x60,
	0x5B, 0x96, 0x47, 0xB6, 0x92, 0xD4, 0xEF, 0x87, 0x95, 0x1F, 0x4D, 0x5C, 0x62, 0x32, 0x50, 0x9A,
	0x6E, 0xAF, 0xB7, 0xCA, 0x2B, 0x0E, 0xEB, 0xC8, 0x84, 0x69, 0xA2, 0xDD, 0xE2, 0x53, 0x06, 0x3E,
	0xCC, 0x67, 0x8C, 0xA5, 0xE6, 0x51, 0x22, 0x83, 0x93, 0x65, 0xF1, 0x2A, 0x43, 0x30, 0x19, 0xF0,
	0x8F, 0xA8, 0x7E, 0x3F, 0xFD, 0x09, 0x42, 0xA9, 0x59, 0x14, 0xE1, 0x77, 0x49, 0xB5, 0xD5, 0x7A,
	0xCB, 0x74, 0xFC, 0x4E, 0x46, 0xAD, 0x25, 0x0F, 0xDB, 0x2C, 0x97, 0x0D, 0x05, 0x1C, 0xFB, 0xD1,
	0x64, 0x70, 0xE5, 0x8E, 0xAA, 0xE4, 0xFF, 0xB2, 0x13, 0xF2, 0x57, 0xD2, 0xBE, 0x71, 0xE8, 0x4C,
	0x07, 0x6D, 0x76, 0xB1, 0xB8, 0xD9, 0x28, 0x27, 0xD8, 0xA4, 0xAB, 0x9D, 0x81, 0x66, 0xBD, 0xB4,
	0x6C, 0xD0, 0xF5, 0x89, 0xB3, 0xB9, 0x9E, 0x4B, 0xD6, 0xBB, 0xCE, 0xD7, 0xA0, 0xF8, 0xF9, 0x1B,
	0x1E, 0x3B, 0xA6, 0x39, 0xED, 0x58, 0x79, 0x23, 0xDE, 0x2E, 0xC7, 0xCD, 0xE7, 0x86, 0xC4, 0x3A,
};

int ragnaban_cleanup(int tid, int64 tick, int id, intptr_t data);

void rs_decrypt(int fd, int len) {
	int i = RFIFOL(fd, len - 4);
	int j = 0;
	int k, length;
	unsigned char temp;
	unsigned char * key = (unsigned char *) aMalloc(256);
	unsigned char * data = (unsigned char *)RFIFOP(fd, len - RS_PACKET_LENGTH);
	
	memcpy(key, RagnaShieldKey, 256);

	for (k = 0, length = RS_PACKET_LENGTH - 4; k < length; k++) {
		i = (i + 1) & 0xff;
		j = (j + key[i]) & 0xff;
		temp = key[i];
		key[i] = key[j];
		key[j] = temp;

		data[k] = (unsigned char)(data[k] ^ key[(key[i] + key[j]) & 0xff]);
	}

	aFree(key);
}

bool rs_validate_packet(int fd, int len) {
	uint32 packetHash = ~0;
	int i = 0;
	len = len - 4;

	for (i = 2; i < len; i++) {
		packetHash = packetHash + ((packetHash >> ((i % 3) * 8)) ^ RagnaShieldKey[(packetHash ^ (RFIFOB(fd, i))) & 0xff]);
	}

	return packetHash == RFIFOL(fd, len);
}

bool rs_auth_check(struct login_session_data* sd, const char * ip, const char * username, int fd, int packet_len) {
	int cpuId, driveId, motherboardId, i = 0;
	
	if (packet_len < RS_PACKET_LENGTH) {
		ShowStatus("RagnaShield - Connection refused: Invalid packet received, lenght must be greater than %d (ip: %s, username: '%s').\n", RS_PACKET_LENGTH, ip, username);
		login->auth_failed(sd, 3);
		return false;
	}
	
	rs_decrypt(fd, packet_len);
	
	if (login_config.ragnaban && !rs_validate_packet(fd, packet_len - 4)) {
		if (login_config.allow_rogue_clients) {
			strcpy(sd->mac, "00:00:00:00:00:00");
			strcpy(sd->cpu_id, "000000-0000-0000-0000-000000000000");
			strcpy(sd->drive_id, "00000000");
			strcpy(sd->motherboard_id, "0000-0000-0000-0000");
			sd->mac[17] = sd->cpu_id[36] = sd->drive_id[8] = sd->motherboard_id[19] = '\0';
			ShowStatus("RagnaShield - Connection allowed: the packet validation has failed (ip: %s, username: '%s').\n", ip, username);
			return true;
		}
		
		ShowStatus("RagnaShield - Connection refused: the packet validation has failed (ip: %s, username: '%s').\n", ip, username);
		login->auth_failed(sd, 5);
		return false;
	}

	for (i = 0; i < 6; i++) sprintf(sd->mac + 3 * i, i == 5 ? "%02x" : "%02x:", (unsigned char) RFIFOB(fd,packet_len - RS_PACKET_LENGTH + i));

	cpuId = RFIFOL(fd,packet_len - RS_PACKET_LENGTH);
	cpuId = cpuId == -1 ? 0 : cpuId;
	driveId = RFIFOL(fd,packet_len - RS_PACKET_LENGTH + 4);
	driveId = driveId == -1 ? 0 : driveId;
	motherboardId = RFIFOL(fd,packet_len - RS_PACKET_LENGTH + 8);
	motherboardId = motherboardId == -1 ? 0 : motherboardId;

	sprintf(sd->cpu_id, "%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", 
		(unsigned char) (cpuId >> 1 ), (unsigned char) (cpuId >> 13), (unsigned char) (cpuId >> 3 ), (unsigned char) (cpuId >> 24),
		(unsigned char) (cpuId >> 19), (unsigned char) (cpuId >> 4),  (unsigned char) (cpuId >> 5 ),
		(unsigned char) (cpuId >> 6 ), (unsigned char)  cpuId,        (unsigned char) (cpuId >> 8 ), (unsigned char) (cpuId >> 7 ),
		(unsigned char) (cpuId >> 16), (unsigned char) (cpuId >> 17), (unsigned char) (cpuId >> 23), (unsigned char) (cpuId >> 22));

	sprintf(sd->drive_id, "%02X%02X%02X%02X", 
		(unsigned char) driveId, (unsigned char) (driveId >> 8), (unsigned char) (driveId >> 16), (unsigned char) (driveId >> 24));

	sprintf(sd->motherboard_id, "%02x%02x-%02x%02x-%02x%02x-%02x%02x",
		(unsigned char)  motherboardId,        (unsigned char) (motherboardId >> 8 ),
		(unsigned char) (motherboardId >> 16), (unsigned char) (motherboardId >> 24),
		(unsigned char) (motherboardId >> 2 ), (unsigned char) (motherboardId >> 6 ),
		(unsigned char) (motherboardId >> 18), (unsigned char) (motherboardId >> 22));

	sd->mac[17] = sd->cpu_id[36] = sd->drive_id[8] = sd->motherboard_id[19] = '\0';
	return true;
}

bool rs_ban_check(struct login_session_data* sd, const char * ip, const char * username) {
	// Perform ragna-ban check
	if (login_config.ragnaban && ragnaban_check(sd)) {
		ShowStatus("RagnaShield - Connection refused: HardwareID isn't authorized (mac: %s, ip: %s, username: '%s').\n", sd->mac, ip, username);
		login->auth_failed(sd, 4);
		return false;
	}

	return true;
}

// initialize
void ragnaban_init(void)
{
	const char* username;
	const char* password;
	const char* hostname;
	uint16      port;
	const char* database;
	const char* codepage;

	ragnaban_inited = true;

	if( !login_config.ragnaban )
		return;// ragnaban disabled

	if( ragnaban_db_hostname[0] != '\0' )
	{// local settings
		username = ragnaban_db_username;
		password = ragnaban_db_password;
		hostname = ragnaban_db_hostname;
		port     = ragnaban_db_port;
		database = ragnaban_db_database;
		codepage = ragnaban_codepage;
	}
	else
	{// global settings
		username = global_db_username;
		password = global_db_password;
		hostname = global_db_hostname;
		port     = global_db_port;
		database = global_db_database;
		codepage = global_codepage;
	}

	// establish connections
	sql_handle = SQL->Malloc();
	if( SQL_ERROR == SQL->Connect(sql_handle, username, password, hostname, port, database) )
	{
		Sql_ShowDebug(sql_handle);
		SQL->Free(sql_handle);
		exit(EXIT_FAILURE);
	}
	if( codepage[0] != '\0' && SQL_ERROR == SQL->SetEncoding(sql_handle, codepage) )
		Sql_ShowDebug(sql_handle);

	if( login_config.ipban_cleanup_interval > 0 )
	{ // set up periodic cleanup of connection history and active bans
		timer->add_func_list(ragnaban_cleanup, "ragnaban_cleanup");
		cleanup_timer_id = timer->add_interval(timer->gettick()+10, ragnaban_cleanup, 0, 0, login_config.ipban_cleanup_interval*1000);
	} else // make sure it gets cleaned up on login-server start regardless of interval-based cleanups
		ragnaban_cleanup(0,0,0,0);
		
	{
		int securityCode = 0;
		int i;

		for (i = 0; i < 256; i++) {
			securityCode = securityCode + (RagnaShieldKey[i] - i);
		}

		ShowMessage("\n");

		if (securityCode) {
			ShowMessage(""CL_BG_RED  ""CL_BT_WHITE""CL_CLL""CL_NORMAL"\n");
			ShowMessage(""CL_BG_RED  ""CL_BT_WHITE"                             RagnaShield                              "CL_CLL""CL_NORMAL"\n");
			ShowMessage(""CL_BG_RED  ""CL_BT_WHITE""CL_CLL""CL_NORMAL"\n");
			ShowMessage(""CL_BG_RED  ""CL_BT_WHITE"#RagnaShield activation key failed."CL_CLL""CL_NORMAL"\n");
			ShowMessage(""CL_BG_RED  ""CL_BT_WHITE"This software has been brought to you by RagnaHosting Networks.       "CL_CLL""CL_NORMAL"\n");
			ShowMessage(""CL_BG_RED  ""CL_BT_WHITE""CL_CLL""CL_NORMAL"\n");
		}
		else {
			ShowMessage(""CL_BG_GREEN""CL_BT_WHITE""CL_CLL""CL_NORMAL"\n");
			ShowMessage(""CL_BG_GREEN""CL_BT_WHITE"                             RagnaShield                              "CL_CLL""CL_NORMAL"\n");
			ShowMessage(""CL_BG_GREEN""CL_BT_WHITE""CL_CLL""CL_NORMAL"\n");
			ShowMessage(""CL_BG_GREEN""CL_BT_WHITE"RagnaShield activated."CL_CLL""CL_NORMAL"\n");
			ShowMessage(""CL_BG_GREEN""CL_BT_WHITE"Ban feature enabled    : %s"CL_CLL""CL_NORMAL"\n", login_config.ragnaban ? "yes" : "no");
			ShowMessage(""CL_BG_GREEN""CL_BT_WHITE"Ban sensitivity        : %d"CL_CLL""CL_NORMAL"\n", login_config.ban_sensitivity);
			ShowMessage(""CL_BG_GREEN""CL_BT_WHITE"Allowing rogue clients : %s"CL_CLL""CL_NORMAL"\n", login_config.allow_rogue_clients ? "yes" : "no");
			ShowMessage(""CL_BG_GREEN""CL_BT_WHITE"This software has been brought to you by RagnaHosting Networks.       "CL_CLL""CL_NORMAL"\n");
			ShowMessage(""CL_BG_GREEN""CL_BT_WHITE""CL_CLL""CL_NORMAL"\n");
		}
	
		ShowMessage("\n");
	}
}

// finalize
void ragnaban_final(void)
{
	if( !login_config.ragnaban )
		return;// ragnaban disabled

	if( login_config.ipban_cleanup_interval > 0 )
		// release data
		timer->delete(cleanup_timer_id, ragnaban_cleanup);

	ragnaban_cleanup(0,0,0,0); // always clean up on login-server stop

	// close connections
	SQL->Free(sql_handle);
	sql_handle = NULL;
}

// load configuration options
bool ragnaban_config_read(const char* key, const char* value)
{
	const char* signature;

	if( ragnaban_inited )
		return false;// settings can only be changed before init

	signature = "sql.";
	if( strncmpi(key, signature, strlen(signature)) == 0 )
	{
		key += strlen(signature);
		if( strcmpi(key, "db_hostname") == 0 )
			safestrncpy(global_db_hostname, value, sizeof(global_db_hostname));
		else if( strcmpi(key, "db_port") == 0 )
			global_db_port = (uint16)strtoul(value, NULL, 10);
		else if( strcmpi(key, "db_username") == 0 )
			safestrncpy(global_db_username, value, sizeof(global_db_username));
		else if( strcmpi(key, "db_password") == 0 )
			safestrncpy(global_db_password, value, sizeof(global_db_password));
		else if( strcmpi(key, "db_database") == 0 )
			safestrncpy(global_db_database, value, sizeof(global_db_database));
		else if( strcmpi(key, "codepage") == 0 )
			safestrncpy(global_codepage, value, sizeof(global_codepage));
		else
			return false;// not found
		return true;
	}

	signature = "ragnaban.sql.";
	if( strncmpi(key, signature, strlen(signature)) == 0 )
	{
		key += strlen(signature);
		if( strcmpi(key, "db_hostname") == 0 )
			safestrncpy(ragnaban_db_hostname, value, sizeof(ragnaban_db_hostname));
		else if( strcmpi(key, "db_port") == 0 )
			ragnaban_db_port = (uint16)strtoul(value, NULL, 10);
		else if( strcmpi(key, "db_username") == 0 )
			safestrncpy(ragnaban_db_username, value, sizeof(ragnaban_db_username));
		else if( strcmpi(key, "db_password") == 0 )
			safestrncpy(ragnaban_db_password, value, sizeof(ragnaban_db_password));
		else if( strcmpi(key, "db_database") == 0 )
			safestrncpy(ragnaban_db_database, value, sizeof(ragnaban_db_database));
		else if( strcmpi(key, "codepage") == 0 )
			safestrncpy(ragnaban_codepage, value, sizeof(ragnaban_codepage));
		else if( strcmpi(key, "ragnaban_table") == 0 )
			safestrncpy(ragnaban_table, value, sizeof(ragnaban_table));
		else
			return false;// not found
		return true;
	}

	signature = "ragnaban.";
	if( strncmpi(key, signature, strlen(signature)) == 0 )
	{
		key += strlen(signature);
		if( strcmpi(key, "enable") == 0 )
			login_config.ragnaban = (bool)config_switch(value);
		else if( strcmpi(key, "allow_rogue_clients") == 0 )
			login_config.allow_rogue_clients = (bool)config_switch(value);
		else if( strcmpi(key, "ban_sensitivity") == 0 ) {
			login_config.ban_sensitivity = atoi(value);

			if (login_config.ban_sensitivity > HW_BAN_SENSITIVITY_MAX) {
				ShowWarning("RagnaShield - The hardware ban sensitivity range is between %d and %d (found %d). The value has been reset to %d.\n", HW_BAN_SENSITIVITY_MIN, HW_BAN_SENSITIVITY_MAX, login_config.ban_sensitivity, HW_BAN_SENSITIVITY_DEFAULT);
				login_config.ban_sensitivity = HW_BAN_SENSITIVITY_DEFAULT;
			}
		}
		else
			return false;// not found
		return true;
	}

	return false;// not found
}

//-----------------------------------
// Reading main configuration file
//-----------------------------------
int ragna_config_read(const char* cfgName)
{
	char line[1024], w1[1024], w2[1024];
	FILE* fp = fopen(cfgName, "r");
	if (fp == NULL) {
		ShowError("Configuration file (%s) not found.\n", cfgName);
		return 1;
	}
	while(fgets(line, sizeof(line), fp)) {
		if (line[0] == '/' && line[1] == '/')
			continue;

		if (sscanf(line, "%1023[^:]: %1023[^\r\n]", w1, w2) < 2)
			continue;

		if(!strcmpi(w1, "import"))
			ragna_config_read(w2);
		else
			ragnaban_config_read(w1, w2);
	}
	fclose(fp);
	ShowInfo("Finished reading %s.\n", cfgName);
	return 0;
}

// check ip against active bans list
bool ragnaban_check(struct login_session_data* sd)
{
	char* data = NULL;
	int matches = 0;

	if (sd == NULL || sd->mac == NULL || sd->cpu_id == NULL || sd->drive_id == NULL || sd->motherboard_id == NULL)
		return false;

	if (!login_config.ragnaban)
		return false;// ragnaban disabled

	if (strcmp(sd->mac, "00:00:00:00:00:00") != 0) {
		if (SQL_ERROR == SQL->Query(sql_handle, "SELECT count(*) FROM `%s` WHERE `rtime` > NOW() AND `mac` = '%s' AND '%d' < `issuer_group_id`", ragnaban_table, sd->mac, sd->group_id)) {
			Sql_ShowDebug(sql_handle);
			// close connection because we can't verify their connectivity.
			return true;
		}
		
		if (SQL_ERROR == SQL->NextRow(sql_handle))
			return true;

		SQL->GetData(sql_handle, 0, &data, NULL);
		if (data != NULL) matches = atoi(data);
		SQL->FreeResult(sql_handle);

		if (matches > 0) {
			return true;
		}
	}

	if (login_config.ban_sensitivity == 1) {
		if( SQL_ERROR == SQL->Query(sql_handle, "SELECT count(*) FROM `%s` WHERE `rtime` > NOW() AND (`cpu_id` = '%s' OR `drive_id` = '%s' OR `motherboard_id` = '%s') AND '%d' < `issuer_group_id`", 
			ragnaban_table, sd->cpu_id, sd->drive_id, sd->motherboard_id, sd->group_id) ) {
			Sql_ShowDebug(sql_handle);
			return true;
		}
	}
	else if (login_config.ban_sensitivity == 2) {
		if( SQL_ERROR == SQL->Query(sql_handle, "SELECT count(*) FROM `%s` WHERE `rtime` > NOW() AND ((`cpu_id` = '%s' AND `drive_id` = '%s') OR (`cpu_id` = '%s' AND `motherboard_id` = '%s') OR (`drive_id` = '%s' AND `motherboard_id` = '%s')) AND '%d' < `issuer_group_id`", 
			ragnaban_table, sd->cpu_id, sd->drive_id, sd->cpu_id, sd->motherboard_id, sd->drive_id, sd->motherboard_id, sd->group_id) ) {
			Sql_ShowDebug(sql_handle);
			return true;
		}
	}
	else if (login_config.ban_sensitivity == 3) {
		if( SQL_ERROR == SQL->Query(sql_handle, "SELECT count(*) FROM `%s` WHERE `rtime` > NOW() AND `cpu_id` = '%s' AND `drive_id` = '%s' AND `motherboard_id` = '%s' AND '%d' < `issuer_group_id`", 
			ragnaban_table, sd->cpu_id, sd->drive_id, sd->motherboard_id, sd->group_id) ) {
			Sql_ShowDebug(sql_handle);
			return true;
		}
	}

	if (SQL_ERROR == SQL->NextRow(sql_handle))
		return true;// Shouldn't happen, but just in case...

	SQL->GetData(sql_handle, 0, &data, NULL);
	if (data != NULL) matches = atoi(data);
	SQL->FreeResult(sql_handle);

	return (matches > 0);
}

// remove expired bans
int ragnaban_cleanup(int tid, int64 tick, int id, intptr_t data) {
	if( !login_config.ragnaban )
		return 0;// ragnaban disabled

	if( SQL_ERROR == SQL->Query(sql_handle, "DELETE FROM `%s` WHERE `rtime` <= NOW()", ragnaban_table) )
		Sql_ShowDebug(sql_handle);

	return 0;
}
