/*
 * matched using POSIX regex with REG_EXTENDED
 * see regex(7) and regex(3)
 */

struct tfp_login _logins[] = {
	{ "nologin",
	  { NULL, 0 },
	  { NULL, 0 } },
	{ "immediate password",
	  { NULL, 0 },
	  { ".*password.*", REG_ICASE } },
	{ "default user/pass",
	  { ".*(login|user).*", REG_ICASE },
	  { ".*password.*", REG_ICASE } },
};

struct tfp_login_failed _logins_failed[] = {
	{ { ".*Login incorrect.*", REG_ICASE }, { NULL, 0 } },
	{ { NULL, 0 }, { ".*Login incorrect.*", REG_ICASE } },
	{ { NULL, 0 }, { ".*Bad Password.*", REG_ICASE } },
	{ { NULL, 0 }, { ".*Password:.*", REG_ICASE } },
	{ { NULL, 0 }, { ".*pam_authenticate call failed.*", REG_ICASE } },
};

struct tfp_console _consoles[] = {
	{ "direct shell",
	  { NULL, 0, NULL, 0, ".*(>|#).?$", 0 },
	  { NULL },
	  { NULL, 0 } },
	/* get shell */
	{ "OS7030",
	  { ".*OS7030.*", 0, NULL, 0 , ".*Please select a menu number :$", 0 },
	  { "1" }, /* choice menu, 1. bash shell */
	  { ".*bash-[0-9\\.]#$", 0 } },
	/* fingerprinting only, direct shell */
	{ "Hikvision",
	  { ".*192.0.0.64 login.*", 0, NULL, 0 , ".*($|#) $", 0 }, { NULL }, { NULL, 0 } },
	{ "SMC",
	  { ".*^SMC.*", 0, NULL, 0 , ".*($|#) $", 0 }, { NULL }, { NULL, 0 } },
	/*
	{ "",
	  { "", 0, NULL, 0 , ".*> $", 0 },
	  { "" },
	  { ".*# $", 0 } },
	*/
};

struct tfp_creds _creds[] = {
        /* less probable */
	{ NULL,
	  "admin,root",
	  "duhao" },
	/* first to try */
	{ NULL,
	  ",admin,root,Administrator",
	  ",admin,root,12345,1234,12345678,PleaseChangeMe" },
	/* specific */
	{ "SMC", "admin", "smcadmin" },
};
