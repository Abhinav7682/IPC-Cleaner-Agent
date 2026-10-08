/**
 * IPC Leak Generator Test Harness.
 * Allocates System V Shared Memory segments, Semaphores, and Message Queues,
 * attaches/populates them, detaches, and exits so that attachments reach 0
 * and creator PID terminates, simulating realistic orphaned IPC leaks.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/sem.h>
#include <sys/msg.h>

void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s [--shm <count>] [--size <bytes>] [--sem <count>] [--msg <count>] [--json]\n", prog);
}

int main(int argc, char *argv[]) {
    int shm_count = 1;
    size_t shm_size = 1048576; // 1 MB default
    int sem_count = 0;
    int msg_count = 0;
    int json_output = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--shm") == 0 && i + 1 < argc) {
            shm_count = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--size") == 0 && i + 1 < argc) {
            shm_size = (size_t)atoll(argv[++i]);
        } else if (strcmp(argv[i], "--sem") == 0 && i + 1 < argc) {
            sem_count = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--msg") == 0 && i + 1 < argc) {
            msg_count = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--json") == 0) {
            json_output = 1;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        }
    }

    int *created_shm = (int *)malloc(sizeof(int) * (shm_count > 0 ? shm_count : 1));
    int *created_sem = (int *)malloc(sizeof(int) * (sem_count > 0 ? sem_count : 1));
    int *created_msg = (int *)malloc(sizeof(int) * (msg_count > 0 ? msg_count : 1));
    int shm_actual = 0;
    int sem_actual = 0;
    int msg_actual = 0;

    // 1. Allocate Shared Memory segments
    for (int i = 0; i < shm_count; i++) {
        int shmid = shmget(IPC_PRIVATE, shm_size, IPC_CREAT | 0600);
        if (shmid >= 0) {
            void *addr = shmat(shmid, NULL, 0);
            if (addr != (void *)-1) {
                // Fill first 64 bytes with test signature
                snprintf((char *)addr, 64, "IPC_CLEANER_LEAK_TEST_SEGMENT_%d_PID_%d", i, (int)getpid());
                shmdt(addr);
            }
            created_shm[shm_actual++] = shmid;
        } else {
            perror("shmget failed");
        }
    }

    // 2. Allocate Semaphores
    for (int i = 0; i < sem_count; i++) {
        int semid = semget(IPC_PRIVATE, 1, IPC_CREAT | 0600);
        if (semid >= 0) {
            created_sem[sem_actual++] = semid;
        } else {
            perror("semget failed");
        }
    }

    // 3. Allocate Message Queues
    for (int i = 0; i < msg_count; i++) {
        int msqid = msgget(IPC_PRIVATE, IPC_CREAT | 0600);
        if (msqid >= 0) {
            created_msg[msg_actual++] = msqid;
        } else {
            perror("msgget failed");
        }
    }

    if (json_output) {
        printf("{\"pid\": %d, \"shm\": [", (int)getpid());
        for (int i = 0; i < shm_actual; i++) {
            printf("%d%s", created_shm[i], (i + 1 < shm_actual) ? ", " : "");
        }
        printf("], \"sem\": [");
        for (int i = 0; i < sem_actual; i++) {
            printf("%d%s", created_sem[i], (i + 1 < sem_actual) ? ", " : "");
        }
        printf("], \"msg\": [");
        for (int i = 0; i < msg_actual; i++) {
            printf("%d%s", created_msg[i], (i + 1 < msg_actual) ? ", " : "");
        }
        printf("], \"bytes_per_shm\": %zu}\n", shm_size);
    } else {
        printf("[LEAK GENERATOR] Created %d SHM segments (%zu bytes each), %d Semaphores, %d Message Queues (Creator PID: %d)\n",
               shm_actual, shm_size, sem_actual, msg_actual, (int)getpid());
        for (int i = 0; i < shm_actual; i++) printf("  SHMID: %d\n", created_shm[i]);
        for (int i = 0; i < sem_actual; i++) printf("  SEMID: %d\n", created_sem[i]);
        for (int i = 0; i < msg_actual; i++) printf("  MSQID: %d\n", created_msg[i]);
    }

    free(created_shm);
    free(created_sem);
    free(created_msg);

    // Process exits without calling IPC_RMID!
    // The segments are now abandoned with nattch == 0 and dead creator PID.
    return 0;
}
