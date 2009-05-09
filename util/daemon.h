#ifndef RSEUTIL_PIDFILE_H
#define RSEUTIL_PIDFILE_H

#define daemon_pidfile { 'P', "pidfile", CONFIG_STR, {}, NULL, "pid file" }

extern void envuidgid(void);
extern void pidfile_create(const char *pidfile);
extern void util_daemonize(char *program_name, char *pidfile);

#endif
