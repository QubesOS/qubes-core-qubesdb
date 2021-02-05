#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef WIN32
#include <windows.h>
#include <getopt.h>
#else
#include <unistd.h>
#endif

#include <qubesdb-client.h>

int opt_fullpath = 0;
int opt_raw = 0;
int opt_quiet = 0;
int opt_watch_count = 1;
int opt_wait = 0;

enum {
    DO_READ = 1,
    DO_WRITE,
    DO_RM,
    DO_MULTIREAD,
    DO_LIST,
    DO_WATCH
} qdb_cmd;

void encode_and_print_value(char *val) {
    size_t i;
    size_t len;

    if (opt_raw) {
        printf("%s", val);
        return;
    }
    len = strlen(val);
    for (i = 0; i < len; i++) {
        if (val[i] >= 0x20 && (unsigned char)val[i] < 0x80)
            printf("%c", val[i]);
        else
#ifndef WIN32
            printf("\\x%02hhx", val[i]);
#else
            /* windows doesn't support 'h' modifier */
            printf("\\x%02x", val[i]);
#endif
    }
}

int cmd_read(qdb_handle_t h, int argc, char **args) {
    int i;
    char *value;
    int anything_failed = 0;

    for (i=0; i < argc; i++) {
        value = qdb_read(h, args[i], NULL);
        if (opt_wait) {
            qdb_watch(h, args[i]);
            while (!(value = qdb_read(h, args[i], NULL)))
            {
                qdb_read_watch(h);
            }
        }
        if (value) {
            if (opt_fullpath)
                printf("%s = ", args[i]);
            encode_and_print_value(value);
            printf("\n");
        } else {
            if (!opt_quiet) {
                fprintf(stderr, "Failed to read %s\n", args[i]);
            }
            anything_failed = 1;
        }
    }

    return anything_failed;
}

int cmd_multiread(qdb_handle_t h, int argc, char **args) {
    int i, j;
    char **path_value;
    int anything_failed = 0;
    size_t basepath_len;

    for (i=0; i < argc; i++) {
        if (opt_fullpath)
            basepath_len = 0;
        else
            basepath_len = strlen(args[i]);
        path_value = qdb_multiread(h, args[i], NULL, NULL);
        if (!path_value) {
            if (!opt_quiet)
                fprintf(stderr, "Failed to read %s\n", args[i]);
            anything_failed = 1;
            continue;
        }
        j = 0;
        while (path_value[j]) {
            printf("%s = ", path_value[j]+basepath_len);
            encode_and_print_value(path_value[j+1]);
            printf("\n");
            free(path_value[j]);
            free(path_value[j+1]);
            j += 2;
        }
    }

    return anything_failed;
}

int cmd_write(qdb_handle_t h, int argc, char **args) {
    int i;
    int anything_failed = 0;

    if (argc % 2) {
        fprintf(stderr, "Invalid number of parameters\n");
        return 1;
    }

    for (i = 0; i < argc; i += 2) {
        if (!qdb_write(h, args[i], args[i+1], (unsigned int)strlen(args[i+1]))) {
            if (!opt_quiet)
                fprintf(stderr, "Failed to write %s\n", args[i]);
            anything_failed = 1;
        }
    }
    return anything_failed;
}

int cmd_rm(qdb_handle_t h, int argc, char **args) {
    int i;
    int anything_failed = 0;

    for (i = 0; i < argc; i++) {
        if (!qdb_rm(h, args[i])) {
            if (!opt_quiet)
                fprintf(stderr, "Failed to remove %s\n", args[i]);
            anything_failed = 1;
        }
    }
    return anything_failed;
}

int cmd_list(qdb_handle_t h, int argc, char **args) {
    int i;
    char **paths;
    size_t basepath_len;

    if (argc != 1) {
        fprintf(stderr, "LIST command accept only one path\n");
        return 1;
    }
    if (opt_fullpath)
        basepath_len = 0;
    else
        basepath_len = strlen(args[0]);
    paths = qdb_list(h, args[0], NULL);
    if (!paths) {
        if (!opt_quiet)
            fprintf(stderr, "Failed to get entries list\n");
        return 1;
    }
    i = 0;
    while (paths[i]) {
        printf("%s\n", paths[i]+basepath_len);
        free(paths[i]);
        i++;
    }
    return 0;
}

int cmd_watch(qdb_handle_t h, int argc, char **args) {
    int i;
    char *fired_watch;

    if (argc == 0)
        return 0;

    for (i = 0; i < argc; i++) {
        if (!qdb_watch(h, args[i])) {
            if (!opt_quiet)
                fprintf(stderr, "Failed to setup watch on %s\n", args[i]);
            return 1;
        }
    }

    while (opt_watch_count--) {
        fired_watch = qdb_read_watch(h);
        if (!fired_watch) {
            if (!opt_quiet)
                fprintf(stderr, "Failed to read watch\n");
            return 1;
        }
        printf("%s\n", fired_watch);
    }

    return 0;
}

int parse_cmd(char *cmd_str) {
    if (!strcmp(cmd_str, "read"))
        return DO_READ;
    else if (!strcmp(cmd_str, "write"))
        return DO_WRITE;
    else if (!strcmp(cmd_str, "rm"))
        return DO_RM;
    else if (!strcmp(cmd_str, "multiread"))
        return DO_MULTIREAD;
    else if (!strcmp(cmd_str, "list"))
        return DO_LIST;
    else if (!strcmp(cmd_str, "watch"))
        return DO_WATCH;
    else
        return 0;
}

void usage(char *argv0) {
    fprintf(stderr,
            "Usage: %s [-frq] [-c <command>] [-d <destination domain>] \n"
            "       [command arguments]\n", argv0);
    fprintf(stderr, "  -f - print full path (affects reading commands)\n");
    fprintf(stderr, "  -r - print raw value (affects reading commands)\n");
    fprintf(stderr, "  -q - quiet - do not print error\n");
    fprintf(stderr, "  -c <command> - specify command\n");
    fprintf(stderr, "  -d <domain> - specify destination domain, available only in dom0\n");
    fprintf(stderr, "  -w - wait for any value (possibly empty)\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Available commands:\n");
    fprintf(stderr, "  read path [path...] - read value(s)\n");
    fprintf(stderr, "  write path value [path value...] - write value(s)\n");
    fprintf(stderr, "  rm path [path...] - remove value(s)\n");
    fprintf(stderr, "  multiread path [path...] - read all entries matching given path\n");
    fprintf(stderr, "  list path - list paths mathing given argument\n");
    fprintf(stderr, "  watch [-n N] path [path...] - watch given path(s) for "
            "modifications\n");
    fprintf(stderr, "    if -n given you can specify how many events should "
            "be received before terminating\n");
}

int main(int argc, char **argv) {
    char *cmd_argv0;
    char *dest_domain = NULL;
    int do_cmd = 0;
    int ret;
    int opt;
    qdb_handle_t h;

    if ((cmd_argv0=strchr(argv[0], '-'))) {
        cmd_argv0++;
        do_cmd = parse_cmd(cmd_argv0);
    }

#ifndef WIN32
    while ((opt = getopt(argc, argv, "hc:d:n:frqw")) != -1)
#else
    while ((opt = getopt(argc, argv, "hc:d:n:frqw")) != 0)
#endif
    {
        switch (opt) {
            case 'c':
                do_cmd = parse_cmd(optarg);
                /* handle invalid command later */
                break;
            case 'd':
                dest_domain = optarg;
                break;
            case 'f':
                opt_fullpath = 1;
                break;
            case 'r':
                opt_raw = 1;
                break;
            case 'q':
                opt_quiet = 1;
                break;
            case 'w':
                opt_wait = 1;
                break;
            case 'n':
                opt_watch_count = atoi(optarg);
                if (do_cmd != DO_WATCH) {
                    fprintf(stderr, "-n valid only for watch command\n");
                    exit(1);
                }
                break;
            case 'h':
                usage(argv[0]);
                exit(0);
#ifndef WIN32
            default:
                usage(argv[0]);
                exit(1);
#endif
        }
    }

    if (argc <= 1 || do_cmd == 0) {
        usage(argv[0]);
        exit(0);
    }

    h = qdb_open(dest_domain);
    if (!h) {
        if (!opt_quiet)
            fprintf(stderr, "Failed connect to %s daemon\n", dest_domain ? dest_domain : "local");
        exit(1);
    }

#ifdef WIN32
    optind -= 2;
#endif
    switch (do_cmd) {
        case DO_READ:
            ret = cmd_read(h, argc-optind, argv+optind);
            break;
        case DO_WRITE:
            ret = cmd_write(h, argc-optind, argv+optind);
            break;
        case DO_RM:
            ret = cmd_rm(h, argc-optind, argv+optind);
            break;
        case DO_MULTIREAD:
            ret = cmd_multiread(h, argc-optind, argv+optind);
            break;
        case DO_LIST:
            ret = cmd_list(h, argc-optind, argv+optind);
            break;
        case DO_WATCH:
            ret = cmd_watch(h, argc-optind, argv+optind);
            break;
        default:
            if (!opt_quiet)
                fprintf(stderr, "Unknown command\n");
            ret = 1;
            break;
    }
    qdb_close(h);
    return ret;
}
