#include "parser.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>

struct process_info {
    pid_t pid;
    const struct expr *cmd;
    int pipe_fd[2];  // [0] - read, [1] - write
    struct process_info *next;
    struct process_info *prev;
};

static struct process_info *process_list = NULL;

static void register_process(pid_t pid, const struct expr *cmd, int pipe_fd[2]) {
    struct process_info *proc = malloc(sizeof(struct process_info));
    if (!proc) {
        perror("malloc");
        exit(1);
    }
    proc->pid = pid;
    proc->cmd = cmd;
    if (pipe_fd) {
        proc->pipe_fd[0] = pipe_fd[0];
        proc->pipe_fd[1] = pipe_fd[1];
    } else {
        proc->pipe_fd[0] = proc->pipe_fd[1] = -1;
    }
    proc->next = process_list;
    proc->prev = NULL;
    if (process_list) process_list->prev = proc;
    process_list = proc;
}

static void remove_process(pid_t pid) {
    struct process_info *curr = process_list;
    while (curr) {
        if (curr->pid == pid) {
            if (curr->prev) curr->prev->next = curr->next;
            if (curr->next) curr->next->prev = curr->prev;
            if (curr == process_list) process_list = curr->next;
            free(curr);
            return;
        }
        curr = curr->next;
    }
}

static void terminate_all_processes() {
    struct process_info *curr = process_list;
    while (curr) {
        kill(curr->pid, SIGTERM);
        struct process_info *next = curr->next;
        free(curr);
        curr = next;
    }
    process_list = NULL;
}

static int execute_command(const struct expr *cmd, int input_fd, int output_fd) {
    if (cmd == NULL || cmd->type != EXPR_TYPE_COMMAND) return -1;

    int pipe_fd[2] = {-1, -1};
    if (cmd->next && cmd->next->type == EXPR_TYPE_PIPE) {
        if (pipe(pipe_fd) < 0) {
            perror("pipe");
            exit(1);
        }
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(1);
    }

    if (pid == 0) {  // Дочерний процесс
        if (input_fd != STDIN_FILENO) {
            dup2(input_fd, STDIN_FILENO);
            close(input_fd);
        }
        if (output_fd != STDOUT_FILENO) {
            dup2(output_fd, STDOUT_FILENO);
            close(output_fd);
        }

        if (pipe_fd[0] != -1) close(pipe_fd[0]);
        if (pipe_fd[1] != -1) close(pipe_fd[1]);

        char **args = malloc((cmd->cmd.arg_count + 2) * sizeof(char *));
        if (!args) {
            perror("malloc");
            exit(1);
        }

        args[0] = cmd->cmd.exe;
        for (uint32_t i = 0; i < cmd->cmd.arg_count; ++i) {
            args[i + 1] = cmd->cmd.args[i];
        }
        args[cmd->cmd.arg_count + 1] = NULL;

        execvp(args[0], args);
        perror("execvp");
        exit(1);
    }

    register_process(pid, cmd, pipe_fd);

    if (pipe_fd[1] != -1) close(pipe_fd[1]);

    int status;
    waitpid(pid, &status, 0);
    remove_process(pid);

    return pipe_fd[0];
}

static int execute_pipeline(const struct expr *e) {
    int input_fd = STDIN_FILENO;
    int last_status = 0;

    while (e) {
        if (e->type == EXPR_TYPE_COMMAND) {
            int pipe_out = execute_command(e, input_fd, STDOUT_FILENO);
            if (input_fd != STDIN_FILENO) close(input_fd);
            input_fd = pipe_out;
        }
        e = e->next;
    }

    return last_status;
}

static void execute_command_list(const struct expr *e) {
    int last_status = 0;

    while (e) {
        if (e->type == EXPR_TYPE_COMMAND || e->type == EXPR_TYPE_PIPE) {
            last_status = execute_pipeline(e);
            while (e && e->type == EXPR_TYPE_PIPE) e = e->next;
        } else if (e->type == EXPR_TYPE_AND) {
            if (last_status != 0) break;
        } else if (e->type == EXPR_TYPE_OR) {
            if (last_status == 0) break;
        }
        e = e->next;
    }
}

static void execute_command_line(const struct command_line *line) {
    assert(line != NULL);
    execute_command_list(line->head);
}

int main(void) {
    const size_t buf_size = 1024;
    char buf[buf_size];
    int rc;
    struct parser *p = parser_new();

    signal(SIGINT, SIG_IGN);

    while ((rc = read(STDIN_FILENO, buf, buf_size)) > 0) {
        parser_feed(p, buf, rc);
        struct command_line *line = NULL;
        while (true) {
            enum parser_error err = parser_pop_next(p, &line);
            if (err == PARSER_ERR_NONE && line == NULL) break;
            if (err != PARSER_ERR_NONE) {
                printf("Error: %d\n", (int)err);
                continue;
            }
            execute_command_line(line);
            command_line_delete(line);
        }
    }

    terminate_all_processes();
    parser_delete(p);
    return 0;
}

