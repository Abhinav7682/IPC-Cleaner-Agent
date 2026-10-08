#include "ipc_ops.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/sem.h>
#include <sys/msg.h>

#if defined(__APPLE__) || defined(__FreeBSD__)
#define IPC_BUFFER_STRUCT struct shmid_ds
#else
#define IPC_BUFFER_STRUCT struct shmid_ds
#endif

int ipc_remove_shm(int shmid) {
    if (shmctl(shmid, IPC_RMID, NULL) == -1) {
        return -1;
    }
    return 0;
}

int ipc_remove_sem(int semid) {
    if (semctl(semid, 0, IPC_RMID) == -1) {
        return -1;
    }
    return 0;
}

int ipc_remove_msg(int msqid) {
    if (msgctl(msqid, IPC_RMID, NULL) == -1) {
        return -1;
    }
    return 0;
}

int ipc_create_shm(size_t size, int perm) {
    int flags = IPC_CREAT | perm;
    int shmid = shmget(IPC_PRIVATE, size, flags);
    return shmid;
}

int ipc_create_sem(int nsems, int perm) {
    int flags = IPC_CREAT | perm;
    int semid = semget(IPC_PRIVATE, nsems, flags);
    return semid;
}

int ipc_create_msg(int perm) {
    int flags = IPC_CREAT | perm;
    int msqid = msgget(IPC_PRIVATE, flags);
    return msqid;
}

int ipc_get_shm_stat(int shmid, int *nattch, size_t *size) {
    struct shmid_ds ds;
    if (shmctl(shmid, IPC_STAT, &ds) == -1) {
        return -1;
    }
    if (nattch) {
        *nattch = (int)ds.shm_nattch;
    }
    if (size) {
        *size = ds.shm_segsz;
    }
    return 0;
}
