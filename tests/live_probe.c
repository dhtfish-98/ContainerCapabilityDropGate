#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define NET_RAW_BIT (1ULL << 13)

static unsigned long long capability(const char *name) {
    FILE *status = fopen("/proc/self/status", "r");
    if (!status) { perror("status"); exit(2); }
    char *line = NULL;
    size_t size = 0;
    unsigned long long value = 0;
    int found = 0;
    while (getline(&line, &size, status) > 0) {
        if (strncmp(line, name, strlen(name)) == 0 && line[strlen(name)] == ':') {
            if (sscanf(line + strlen(name) + 1, "%llx", &value) != 1) exit(2);
            found = 1;
            break;
        }
    }
    free(line);
    fclose(status);
    if (!found) exit(2);
    return value;
}

static int examine(const char *phase, int expect_raw) {
    unsigned long long eff = capability("CapEff");
    unsigned long long bnd = capability("CapBnd");
    unsigned long long prm = capability("CapPrm");
    unsigned long long inh = capability("CapInh");
    unsigned long long amb = capability("CapAmb");
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    int error = errno;
    int operation = fd >= 0;
    if (fd >= 0) close(fd);
    printf("PHASE=%s CapEff=%016llx CapPrm=%016llx CapBnd=%016llx CapInh=%016llx CapAmb=%016llx RAW_SOCKET=%s errno=%d\n",
           phase, eff, prm, bnd, inh, amb, operation ? "ALLOW" : "DENY", operation ? 0 : error);
    fflush(stdout);
    if ((!!(eff & NET_RAW_BIT) != expect_raw) ||
        (!!(prm & NET_RAW_BIT) != expect_raw) ||
        (!!(bnd & NET_RAW_BIT) != expect_raw) || inh != 0 || amb != 0 || operation != expect_raw ||
        (!expect_raw && error != EPERM)) return 1;
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "hold") == 0) {
        puts("HOLD_READY");
        fflush(stdout);
        sleep(30);
        return 0;
    }
    if (argc != 2 && argc != 3) return 2;
    if (strcmp(argv[1], "allow") != 0 && strcmp(argv[1], "deny") != 0) return 2;
    int expected = strcmp(argv[1], "allow") == 0;
    if (argc == 3 && strcmp(argv[2], "child") == 0)
        return examine("CHILD_EXEC", expected);
    if (argc == 3 && strcmp(argv[2], "exec-child") == 0)
        return examine("OCI_EXEC_CHILD", expected);
    if (argc == 3 && strcmp(argv[2], "exec") != 0) return 2;
    const int is_exec = argc == 3;
    if (examine(is_exec ? "OCI_EXEC" : "INIT", expected) != 0) return 1;
    pid_t child = fork();
    if (child < 0) return 2;
    if (child == 0) {
        execl("/bin/live-probe", "/bin/live-probe", argv[1],
              is_exec ? "exec-child" : "child", (char *)0);
        perror("exec");
        _exit(2);
    }
    int status = 0;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return 1;
    puts("PROBE_RESULT=PASS");
    return 0;
}
