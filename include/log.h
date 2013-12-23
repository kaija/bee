#ifndef __PLOG_H
#define __PLOG_H
#define PLOG_LEVEL_DEBUG   0
#define PLOG_LEVEL_INFO    1
#define PLOG_LEVEL_WARN    2
#define PLOG_LEVEL_ERROR   3
#define PLOG_LEVEL_FATAL   4

#define __INFO__  __FILE__,__LINE__,__func__

#define PLOG_TO_SCREEN       1
#define PLOG_TO_FILE         2
#define PLOG_TO_SYSLOG       4

enum{
    PLOG_IS_FILE,
    PLOG_IS_DIR,
    PLOG_IS_UNKNOWN,
    PLOG_IS_NONEXIST,
    PLOG_IS_ERROR,
};

#define PLOG_TRUE        1
#define PLOG_FALSE       0
#define PLOG_PATH_LEN    128
#define PLOG(level, fmt, args...)  plogger_print(level,__FILE__,__LINE__,__func__, fmt, ##args)
int plogger_init();
int plogger_shutdown();
int plogger_set_path(char *path);
int plogger_enable_screen(int level);
int plogger_enable_file(int level);
int plogger_enable_syslog(int level);
int plogger_disable_screen();
int plogger_disable_file();
int plogger_disable_syslog();
int plogger_print(int level, const char *file, int line, const char *func, char *fmt, ...);
#endif
