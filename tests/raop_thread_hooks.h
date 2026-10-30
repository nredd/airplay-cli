/*
 * Force-included into the test build of libraop's raop_client.c so every
 * thread create/join it performs is routed through the test's bookkeeping.
 */
#ifndef RAOP_THREAD_HOOKS_H
#define RAOP_THREAD_HOOKS_H

#include <pthread.h>

int raop_test_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                             void *(*start)(void *), void *arg);
int raop_test_pthread_join(pthread_t thread, void **retval);

#define pthread_create raop_test_pthread_create
#define pthread_join raop_test_pthread_join

#endif
