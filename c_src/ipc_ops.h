#ifndef IPC_OPS_H
#define IPC_OPS_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Remove shared memory segment via shmctl(shmid, IPC_RMID, NULL).
 * Returns 0 on success, or -1 on error (errno is set).
 */
int ipc_remove_shm(int shmid);

/**
 * Remove semaphore set via semctl(semid, 0, IPC_RMID).
 * Returns 0 on success, or -1 on error (errno is set).
 */
int ipc_remove_sem(int semid);

/**
 * Remove message queue via msgctl(msqid, IPC_RMID, NULL).
 * Returns 0 on success, or -1 on error (errno is set).
 */
int ipc_remove_msg(int msqid);

/**
 * Create a new private shared memory segment.
 * Returns shmid on success, or -1 on error.
 */
int ipc_create_shm(size_t size, int perm);

/**
 * Create a new private semaphore set.
 * Returns semid on success, or -1 on error.
 */
int ipc_create_sem(int nsems, int perm);

/**
 * Create a new private message queue.
 * Returns msqid on success, or -1 on error.
 */
int ipc_create_msg(int perm);

/**
 * Get attachment count and size for a shared memory segment.
 * Returns 0 on success, or -1 on error.
 */
int ipc_get_shm_stat(int shmid, int *nattch, size_t *size);

#ifdef __cplusplus
}
#endif

#endif /* IPC_OPS_H */
