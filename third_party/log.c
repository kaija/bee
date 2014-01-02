#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <stdarg.h>
#ifdef HAVE_SYSPLOG
#include <syslog.h>
#endif //HAVE_SYSPLOG
#include "log.h"

#ifdef __ANDROID__
#include <android/log.h>
#endif
int plogger_is_exist(char *path)
{
    if(!path) return PLOG_IS_ERROR;
    struct stat s;
    if(stat(path, &s) == 0){
        if(s.st_mode && S_IFDIR) return PLOG_IS_DIR;
        if(s.st_mode && S_IFREG) {
            return PLOG_IS_FILE;
        }
        return PLOG_IS_UNKNOWN;
    }
    return PLOG_IS_NONEXIST;
}

static struct logger{
    FILE        *fp;                //Write file descriptor
    char        path[PLOG_PATH_LEN]; //Log file path
    char        mode;
    int         level_file;         //Log level of file
    int         level_screen;       //Log level of screen
    int         level_syslog;       //Log level of syslog
    int         rotate;             //Rotate the log
    long int	cur_size;           //Current file size
    long int    max_size;           //in KB
} plog = {
    NULL,
    "/tmp/p2p.log",
    PLOG_TO_SCREEN,
    PLOG_LEVEL_DEBUG,
    PLOG_LEVEL_DEBUG,
    PLOG_LEVEL_DEBUG,
    PLOG_TRUE,
    0,
    1048576
};

struct {
    char text[16];
} plog_text[] = {
    {"DEBUG"},
    {"INFO"},
    {"WARN"},
    {"ERROR"},
    {"FATAL"}
};
static char *plogger_level_text(int level)
{
    return plog_text[level].text;
}
int plogger_rotate()
{
    char new_file[PLOG_PATH_LEN];
    if(plog.fp) fclose(plog.fp);
    snprintf(new_file,PLOG_PATH_LEN,"%s.1",plog.path);
    rename(plog.path, new_file);
    printf("File rotate\n");
    plog.fp = NULL;
    return 0;
}
int plogger_print(int level, const char *file, int line, const char *func, char *fmt, ...)
{
    char buf[2048];
    va_list vl;
    va_start(vl, fmt);
    vsnprintf(buf, sizeof(buf), fmt, vl);
    if((plog.mode & PLOG_TO_SCREEN) && level >= plog.level_screen){
#ifdef __ANDROID__
        __android_log_vprint(level + 3, file, fmt, vl);
#else
        fprintf(stdout, "[%s]%s:%d(%s) %s", plogger_level_text(level), file,line,func,buf);
#endif
    }
    va_end(vl);
    if((plog.mode & PLOG_TO_FILE) && level >= plog.level_file){
        if(!plog.fp) plogger_init();
        char tmp[2100];
        int rc = snprintf(tmp, 2100, "[%s]%s:%d(%s) %s", plogger_level_text(level), file, line, func, buf);
        if(plog.cur_size + rc > plog.max_size){
            printf("rotat file size %ld\n", plog.cur_size);
            plogger_rotate();
            plogger_init();
            fprintf(plog.fp, "%s", tmp);
            fflush(plog.fp);
        }else{
            plog.cur_size+=rc;
            fprintf(plog.fp, "%s", tmp);
            fflush(plog.fp);
        }
    }
#ifdef HAVE_SYSPLOG
    if((plog.mode & PLOG_TO_SYSPLOG) && level >= plog.level_syslog ){
        if(level == PLOG_LEVEL_DEBUG) {
            syslog(PLOG_DEBUG,"[%s]%s:%d(%s) %s", plogger_level_text(level), file,line,func,buf);
        }else if(level == PLOG_LEVEL_INFO) {
            syslog(PLOG_INFO,"[%s]%s:%d(%s) %s", plogger_level_text(level), file,line,func,buf);
        }else if(level == PLOG_LEVEL_WARN) {
            syslog(PLOG_WARNING,"[%s]%s:%d(%s) %s", plogger_level_text(level), file,line,func,buf);
        }else if(level == PLOG_LEVEL_ERROR) {
            syslog(PLOG_ERR,"[%s]%s:%d(%s) %s", plogger_level_text(level), file,line,func,buf);
        }else if(level == PLOG_LEVEL_FATAL) {
            syslog(PLOG_CRIT,"[%s]%s:%d(%s) %s", plogger_level_text(level), file,line,func,buf);
        }
    }
#endif //HAVE_SYSPLOG
    return 0;
}

int plogger_disable_screen()
{
    plog.mode &= ~PLOG_TO_SCREEN;
    return 0;
}
int plogger_disable_file()
{
    plog.mode &= ~PLOG_TO_SCREEN;
    return 0;
}
int plogger_enable_screen(int level)
{
    plog.mode |= PLOG_TO_SCREEN;
    plog.level_screen = level;
    return 0;
}
int plogger_enable_file(int level)
{
    plog.mode |= PLOG_TO_FILE;
    plog.level_file = level;
	plogger_shutdown();
	plogger_init();
    return 0;
}
#ifdef HAVE_SYSPLOG
int plogger_enable_syslog(int level)
{
    plog.mode |= PLOG_TO_SYSPLOG;
    plog.level_syslog = level;
    return 0;
}
int logger_disable_syslog()
{
    plog.mode &= ~PLOG_TO_SYSPLOG;
    return 0;
}
#endif //HAVE_SYSPLOG
int plogger_set_path(char *path)
{
    if(path){
        int ret = plogger_is_exist(path);
        if(ret == PLOG_IS_FILE || ret == PLOG_IS_NONEXIST){
            strncpy(plog.path, path, PLOG_PATH_LEN);
            return PLOG_FALSE;
        }
    }
    return PLOG_FALSE;
}

int plogger_set_file_size(char *size)
{
	if(size) {
		int s = atoi(size);
		printf("get size %d\n", s);
		if(strstr(size, "kb")!=NULL){
			plog.max_size = s * 1024;
		}else if(strstr(size,"mb")!= NULL){
			plog.max_size = s * 1024 * 1024;
			return 0;
		}else{
			return -1;
		}
	}
	return 0;
}

int plogger_init()
{
    printf("logger init\n");
    if(plog.fp == NULL && (plog.mode & PLOG_TO_FILE)){
        plog.fp = fopen(plog.path, "a");
        if(plog.fp){
            printf("Log file opened on %s\n", plog.path);
            if(fseek(plog.fp, 0, SEEK_END) == 0){
                plog.cur_size = ftell(plog.fp);
                printf("log file already used %ld bytes\n", plog.cur_size);
            }
        }else{
            printf("Log initial failure\n");
            return PLOG_FALSE;
        }
    }
    return PLOG_FALSE;
}
int plogger_shutdown()
{
    if(plog.fp) fclose(plog.fp);
    plog.fp = NULL;
    return 0;
}
