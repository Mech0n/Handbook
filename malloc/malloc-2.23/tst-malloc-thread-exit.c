/* Test malloc with concurrent thread termination.
   Copyright (C) 2015-2016 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

/* This thread spawns a number of outer threads, equal to the arena
   limit.  The outer threads run a loop which start and join two
   different kinds of threads: the first kind allocates (attaching an
   arena to the thread; malloc_first_thread) and waits, the second
   kind waits and allocates (wait_first_threads).  Both kinds of
   threads exit immediately after waiting.  The hope is that this will
   exhibit races in thread termination and arena management,
   particularly related to the arena free list.  */

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define TIMEOUT 7

static bool termination_requested;
static int inner_thread_count = 4;
static size_t malloc_size = 32;

static void
__attribute__ ((noinline, noclone))
unoptimized_free (void *ptr)
{
  free (ptr);
}

static void *
malloc_first_thread (void * closure)
{
  pthread_barrier_t *barrier = closure;
  void *ptr = malloc (malloc_size);
  if (ptr == NULL)
    {
      printf ("error: malloc: %m\n");
      abort ();
    }
  int ret = pthread_barrier_wait (barrier);
  if (ret != 0 && ret != PTHREAD_BARRIER_SERIAL_THREAD)
    {
      errno = ret;
      printf ("error: pthread_barrier_wait: %m\n");
      abort ();
    }
  unoptimized_free (ptr);
  return NULL;
}

static void *
wait_first_thread (void * closure)
{
  pthread_barrier_t *barrier = closure;
  int ret = pthread_barrier_wait (barrier);
  if (ret != 0 && ret != PTHREAD_BARRIER_SERIAL_THREAD)
    {
      errno = ret;
      printf ("error: pthread_barrier_wait: %m\n");
      abort ();
    }
  void *ptr = malloc (malloc_size);
  if (ptr == NULL)
    {
      printf ("error: malloc: %m\n");
      abort ();
    }
  unoptimized_free (ptr);
  return NULL;
}

static void *
outer_thread (void *closure)
{
  pthread_t *threads = calloc (sizeof (*threads), inner_thread_count);
  if (threads == NULL)
    {
      printf ("error: calloc: %m\n");
      abort ();
    }

  while (!__atomic_load_n (&termination_requested, __ATOMIC_RELAXED))
    {
      pthread_barrier_t barrier;
      int ret = pthread_barrier_init (&barrier, NULL, inner_thread_count + 1);
      if (ret != 0)
        {
          errno = ret;
          printf ("pthread_barrier_init: %m\n");
          abort ();
        }
      for (int i = 0; i < inner_thread_count; ++i)
        {
          void *(*func) (void *);
          if ((i  % 2) == 0)
            func = malloc_first_thread;
          else
            func = wait_first_thread;
          ret = pthread_create (threads + i, NULL, func, &barrier);
          if (ret != 0)
            {
              errno = ret;
              printf ("error: pthread_create: %m\n");
              abort ();
            }
        }
      ret = pthread_barrier_wait (&barrier);
      if (ret != 0 && ret != PTHREAD_BARRIER_SERIAL_THREAD)
        {
          errno = ret;
          printf ("pthread_wait: %m\n");
          abort ();
        }
      for (int i = 0; i < inner_thread_count; ++i)
        {
          ret = pthread_join (threads[i], NULL);
          if (ret != 0)
            {
              ret = errno;
              printf ("error: pthread_join: %m\n");
              abort ();
            }
        }
      ret = pthread_barrier_destroy (&barrier);
      if (ret != 0)
        {
          ret = errno;
          printf ("pthread_barrier_destroy: %m\n");
          abort ();
        }
    }

  free (threads);

  return NULL;
}

static int
do_test (void)
{
  /* The number of top-level threads should be equal to the number of
     arenas.  See arena_get2.  */
  long outer_thread_count = sysconf (_SC_NPROCESSORS_ONLN);
  if (outer_thread_count >= 1)
    {
      /* See NARENAS_FROM_NCORES in malloc.c.  */
      if (sizeof (long) == 4)
        outer_thread_count *= 2;
      else
        outer_thread_count *= 8;
    }

  /* Leave some room for shutting down all threads gracefully.  */
  int timeout = TIMEOUT - 2;

  pthread_t *threads = calloc (sizeof (*threads), outer_thread_count);
  if (threads == NULL)
    {
      printf ("error: calloc: %m\n");
      abort ();
    }

  for (long i = 0; i < outer_thread_count; ++i)
    {
      int ret = pthread_create (threads + i, NULL, outer_thread, NULL);
      if (ret != 0)
        {
          errno = ret;
          printf ("error: pthread_create: %m\n");
          abort ();
        }
    }

  struct timespec ts = {timeout, 0};
  if (nanosleep (&ts, NULL))
    {
      printf ("error: error: nanosleep: %m\n");
      abort ();
    }

  __atomic_store_n (&termination_requested, true, __ATOMIC_RELAXED);

  for (long i = 0; i < outer_thread_count; ++i)
    {
      int ret = pthread_join (threads[i], NULL);
      if (ret != 0)
        {
          errno = ret;
          printf ("error: pthread_join: %m\n");
          abort ();
        }
    }
  free (threads);

  return 0;
}

#define TEST_FUNCTION do_test ()
#include "../test-skeleton.c"
